# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.

import config
import socket
import thread
import threading
from command import Command
import server
import log
import os
import re
import friend
import hashlib
import json
import version
from select import select
from time import time
import crypto
import M2Crypto
import customexceptions
import validators


logger = log.initialize_logging("fail2ban-p2p." + __name__)

class Node:
    """Handles the self-awareness of the program."""
    __shared_state = {}

    # config attributes
    uid = 0
    name = ""
    addresses = []
    port = 0
    ownerMail = ""
    banTime = 0

    # working attributes
    banList = []
    messageQueue = []
    friends = []
    running = True
    lock = threading.Lock()

    def __init__(self):
        self.__dict__ = self.__shared_state # borg pattern.

    def openSocket(self):
        """
        Opens a server socket on the port specified in the config files, forks away a thread to
        handle the incoming requests.
        """
        logger.info("This is node " + str(self.name) + " (uid=" + str(self.uid) + ") coming up")
        logger.debug("running version: " + version.version)
        try:
            sockets = []
            for a in self.addresses:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.bind((a, int(self.port)))
                    s.listen(1)
                    sockets.append(s)
                except Exception as e:
                    logger.warning("Couldn't bind to address "+a+" (Reason: "+str(e)+")")

            while self.running:
                readable, writable, errored = select(sockets, [], [])
                for sock in readable:
                    client_socket, address = sock.accept()
                    logger.debug("connection from "+address[0])
                    thread.start_new_thread(server.serve, (self, client_socket, address))
        except Exception as e:
            print(e)

    def closeSocket(self):
        """
        Closes the server Socket
        """
        logger.debug("closing socket")
        self.running = False

    def processMessages(self):
        """Locks own instance and acts on incoming messages."""
        self.lock.acquire()
        logger.debug("begin message handling")
        for c in self.messageQueue:
            if not self.uid in c.hops:
                if c.hops[0] == 'local':
                    del c.hops[0]
                # relay if we're not already in the hops list
                c.hops.append(self.uid)
                if c.msgType == 1:
                    # apply friend's trustlevel
                    if not 'Trustlevel' in c.parameter:
                        logger.warn("Incoming Message has no Trustlevel, I won't trust it. Never.")
                        c.parameter['Trustlevel'] = 0;

                    if c.sender != "local":
                        c.parameter['Trustlevel'] = int((float(c.sender.trustLevel)/100 * float(c.parameter['Trustlevel'])/100)*100)
                        logger.debug("Message now has trust level "+ str(c.parameter['Trustlevel']))


                    # Aggregate trustlevel if that IP is already in our database under these conditions:
                    # * Timestamp of the received message has changed
                    # * The originator of this message did not send it before

                    relay = True
                    ipindb = False
                    if len(self.banList) > 0:
                        for ban in self.banList:
                            if ban['AttackerIP'] == c.parameter['AttackerIP']:
                                ipindb = True
                                logger.debug("IP already in database.")

                                if int(ban['Timestamp']) != int(c.parameter['Timestamp']):
                                    if not c.hops[0] in ban['Hops']:
                                        trustold = ban['Trustlevel']
                                        trustnew = int(trustold)+int(c.parameter['Trustlevel'])
                                        if trustnew > 100:
                                            trustnew = 100
                                        ban['Trustlevel'] = trustnew
                                        ban['Hops'].append(c.hops[0])
                                        logger.debug("TrustLevel for this IP is now "+str(trustnew))
                                        c.parameter['Trustlevel'] = trustnew
                                    else:
                                        relay = False
                                        logger.debug("There is already an entry from %s in our database, do nothing with this message." % c.hops[0])
                                else:
                                    relay = False
                                    logger.debug("Timestamp has not changed, do nothing with this message")

                    if not ipindb:
                        self.banList.append({'AttackerIP': c.parameter['AttackerIP'], 'Timestamp': c.parameter['Timestamp'], 'BanTime': self.banTime, 'Trustlevel':c.parameter['Trustlevel'], 'Hops': [c.hops[0]]})
                        logger.debug("Added %s to internal banlist" % (c.parameter['AttackerIP']))

                    # write ban entry to log if the message's trust level is above our own threshold

                    if relay:
                        if int(c.parameter['Trustlevel']) >= int(config.Config().threshold):
                            logger.ban(c.parameter['AttackerIP'])
                        else:
                            logger.debug("Message's trust level (%s) was below our threshold (%s)" % (c.parameter['Trustlevel'], config.Config().threshold))

                        # Relay message
                        for friend in self.friends:
                            logger.debug("sending message to all friends")
                            friend.sendCommand(c)

                if c.msgType == 3:
                    # dump all ips from banlist to the friend who send this dump request
                    sender_uid = c.hops[0]
                    for friend in self.friends:
                        logger.debug("Comparing senders uid (%s) with one of our friends uid (%s)" % (sender_uid, friend.uid))
                        if friend.uid == sender_uid:
                            logger.debug("The message is from our friend %s (uid: %s)" % ( friend.name, friend.uid) )
                            logger.debug("Dumping banlist to %s (uid: %s)" % ( friend.name, friend.uid) )
                            if len(self.banList) > 0:
                                for ban in self.banList:
                                    c = Command()
                                    c.msgType = 1
                                    c.hops = [ self.uid ]
                                    c.protocolVersion = version.protocolVersion
                                    c.parameter = { "AttackerIP": ban['AttackerIP'], "Timestamp": ban['Timestamp'], "Trustlevel": ban['Trustlevel'] }
                                    friend.sendCommand(c)
            else:
                logger.debug("I know this message, I won't resend it to prevent loops")
        logger.debug("end message handling")
        self.messageQueue = []
        logger.debug("deleted processed messages")
        self.lock.release()

    def addMessage(self, command):
        """Locks Instance, adds message to queue, releases instanceLock

        Args:
            * command (obj): command object

        """
        logger.debug("command added to queue")
        self.lock.acquire()
        self.messageQueue.append(command)
        self.lock.release()
        self.processMessages()

    def loadConfig(self):
        """Loads Config and own keypair."""
        c = config.Config()
        self.configPath = c.configPath
        self.configFile = c.configFile

        pubkey_file = open(c.pubkey, 'r').read()
        pubkey = re.findall("-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", pubkey_file, re.DOTALL|re.M)[0]

        logger.debug("our own pubkey is: %s" % pubkey)

        self.uid = str(hashlib.sha224(pubkey).hexdigest())
        logger.debug("that makes our own uid: %s", self.uid)
        self.addresses = c.addresses
        self.port = c.port
        self.ownerMail = c.ownermail
        self.banTime = int(c.banTime)
        self.name = c.name

    def getFriends(self):
        """Reads Friends from config path.

        This iterates over all files in <config path>/friends, extracts all options and
        add these friends to self.friends if their configuration is valid.

        """
        error = False
	friendPath = os.path.join(self.configPath, 'friends')
        friends = [f for f in os.listdir(friendPath) if os.path.isfile(os.path.join(friendPath, f))]
	if not friends:
            logger.warning("No friends found. In order to properly use fail2ban-p2p" +
                           " add at least one friend.")

        for file in friends:
            with open(os.path.join(os.path.join(self.configPath, 'friends'), file), 'r') as f:
                friendinfo = str(f.read())
                f.closed
            try:
                pubkey = re.findall("-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", friendinfo, re.DOTALL|re.M)[0]
            except IndexError:
                logger.warning("No pubkey found in config for " + file)
                error = True
            if pubkey:
                logger.debug("read friend's public key: %s" % pubkey )
                uid = str(hashlib.sha224(pubkey).hexdigest())
            try:
                address = re.search("address\s*=\s*(.*)", friendinfo).group(1)
            except AttributeError:
                logger.warning("address not found in config for " + file)
                error = True
            try:
                port = re.search("port\s*=\s*(.*)", friendinfo).group(1)
                # make sure port is in valid range
                if not 0 < int(port) < 65536:
                    logger.warning("Port is invalid in '%s' friend file, must be between 0 and 65535" % file)
                    error = True
            except AttributeError:
                logger.warning("port not found in config for " + file)
                error = True

            try:
                trustlevel = re.search("trustlevel\s*=\s*(.*)", friendinfo).group(1)
            except AttributeError:
                logger.warning("trustlevel not found in config for" + file)
                error = True

            if not error:
                obj = friend.Friend(name=file, uid=uid, address=address, port=int(port),
                                    trustLevel=int(trustlevel), publicKey=pubkey)
                obj.configpath=os.path.join(os.path.join(self.configPath, 'friends'), file)
                logger.debug("added friend " + file +
                             " (uid=" + uid + ", address=" + address + ", port=" + str(port) +
                             ", trustLevel=" + str(trustlevel) + ")"
                            )
                self.friends.append(obj)
            else:
                logger.error("Could not add friend '%s' due to errors in the config file" % file)


    def verifyMessage(self, message):
        """Verify a message

        Args:
            * message -- message object

        """

        logger.debug("signature in command class is: "+str(message.signature))
        logger.debug("attempting to verify command")

        # semantic verification
        # 1. Parameters for all msgTypes

        # msgType
        if not message.msgType:
            logger.warn("Required parameter 'msgType' is missing in received message.")
            raise customexceptions.InvalidMessage
        else:
            if not validators.isInteger(message.msgType):
                logger.warn("Invalid parameter 'msgType' in received message, can only be an integer.")
                raise customexceptions.InvalidMessage

	# Protocol version
        if not version.protocolVersion == message.protocolVersion:
            logger.warn("The protocol version of the received message (" + str(message.protocolVersion) + ") does not match the protocol version of this node (" + str(version.protocolVersion) + ").")
            raise customexceptions.InvalidProtocolVersion

        # Signature
        if not message.signature:
            logger.warn("Signature is missing in received message")
            raise customexceptions.InvalidMessage

        # Hops
        for h in message.hops:
            if not validators.isAlphaNumeric(h):
                logger.warn("Invalid characters in hops. Only alphanumeric characters are allowed.")
                raise customexceptions.InvalidMessage

        # Parameters
        if not message.parameter:
            logger.warn("Message contains no parameters!")
            raise customexceptions.InvalidMessage

        # 2. parameters for custom message types
        if message.msgType == 1:
            # Verify AttackerIP
            if not ("AttackerIP" in message.parameter):
                logger.warn("Required parameter 'AttackerIP' is missing in received message.")
                raise customexceptions.InvalidMessage
            else:
                if not validators.isIPv4address(message.parameter['AttackerIP']):
                    logger.warn('Invalid parameter "AttackerIP" in received message.')
                    raise customexceptions.InvalidMessage

            # Verify Timestamp
            if not ("Timestamp" in message.parameter):
                logger.warn("Required parameter 'Timestamp' is missing in received message.")
                raise customexceptions.InvalidMessage
            else:
                if not validators.isInteger(message.parameter['Timestamp']):
                    logger.warn('Invalid parameter "Timestamp" in received message.')
                    raise customexceptions.InvalidMessage

            # verify Trustlevel
            if not 'Trustlevel' in message.parameter:
                logger.warn('Required parameter "Trustlevel" in missing in received message.')
                raise customexceptions.InvalidMessage
            else:
                if not (validators.isInteger(message.parameter['Trustlevel']) and 0 <= int(message.parameter['Trustlevel']) <= 100):
                    logger.warn('Invalid parameter "Trustlevel" in received message.')
                    raise customexceptions.InvalidMessage

        elif message.msgType == 2 or message.msgType == 3:
            if not ("TimeFrame" in message.parameter):
                logger.warn("Required parameter 'TimeFrame' is missing in received message.")
                raise customexceptions.InvalidMessage
            else:
                if not validators.isInteger(message.parameter['TimeFrame']):
                    logger.warn('Invalid parameter "TimeFrame" in received message.')
                    raise customexceptions.InvalidMessage

        else:
            logger.warn("Unknown message type: " + str(message.msgType))
            raise customexceptions.InvalidMessage

        # signature
        logger.debug("attempting to verify signature")
        last_hop_uid = message.hops[len(message.hops)-1]
        logger.debug("Last hop's uid is: %s" % ( last_hop_uid ) )

        # look for known signatures
        sender = None
        for friend in self.friends:
            logger.debug("Comparing last hops uid (%s) with one of our friends uid (%s)" % (last_hop_uid, friend.uid))
            if friend.uid == last_hop_uid:
                logger.debug("The message seems to be from our friend %s (uid: %s)" % ( friend.name, friend.uid) )
                sender = friend
                pk = M2Crypto.RSA.load_pub_key(sender.configpath)
                break
            if last_hop_uid == "local": # the message was signed with our own key
                logger.debug("This message was signed with our own key.")
                c = config.Config()
                pk = M2Crypto.RSA.load_pub_key(c.pubkey)
                sender = "local"
                break
        if sender == None:
            logger.warning("The message could not be mapped to one of our friends!")
            raise customexceptions.InvalidSignature

        # load sender's public key
        VerifyEVP = M2Crypto.EVP.PKey()
        # Assign the public key to our VerifyEVP
        VerifyEVP.assign_rsa(pk)
        # Begin verification
        VerifyEVP.verify_init()
        # verify the message against it
        VerifyEVP.verify_update (json.dumps(message.toSerializableDict()))

        if(VerifyEVP.verify_final(message.signature.decode('hex')) != 1):
            logger.warning('Signature doesnt match!')
            return False
        else:
            logger.debug('Signature verified successfully')
            message.sender = sender
            return True



    def dumpBanlist(self, timeframe):
        """Generates List of Bans

        Args:
            * timeframe (int): Show nodes that were inserted this many seconds ago or later

        Returns:
            JSON encoded list of known bans.

        """
        banlist = []
        if not timeframe:
            timeframe = 3600

        timeframestart = int(time()) - int(timeframe)
        logger.debug("Dumping all nodes that were inserted after " + str(timeframestart))
        for entry in self.banList:
            if int(entry['Timestamp']) > int(timeframestart):
                banlist.append(entry)

        return json.dumps(banlist)

    def requestBanlist(self):
        """Request a Ban List from all friends."""
        for friend in self.friends:
            logger.debug("Sending dump request to " + friend.name)
            c = Command()
            c.msgType = 3
            c.hops = [ self.uid ]
            c.protocolVersion = version.protocolVersion
            c.parameter = { "TimeFrame": self.banTime or 3600 }
            friend.sendCommand(c)

    def cleanBanlist(self):
        """Purges expired bans, restarts itself after 60 seconds."""
        logger.debug("Purging all entries from banlist that are older than %s seconds." % self.banTime)
        if len(self.banList) > 0:
            banListKeep = []
            for ban in self.banList:
                if ban['Timestamp'] + self.banTime > time():
                    banListKeep.append(ban)
                else:
                    logger.info("Removed %s from internal banlist because the ban has expired." % ban['AttackerIP'])
            self.banList = banListKeep
        global cleaner
        cleaner = threading.Timer(60,self.cleanBanlist)
        cleaner.start()

    def cleanBanlistStop(self):
        """stops cleanBanlist thread"""
        cleaner.cancel()
