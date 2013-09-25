# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.

import command
import socket
import log

logger = log.initialize_logging("fail2ban-p2p." + __name__)

class Friend:
    """Contains information about friends (i.e. associated nodes).

    Kwargs:
        * name (string): A name for this friend (derived from filename)
        * uid (string): A unique identifier (sha224 of friends public key)
        * address (array): IP Addresses or Domains where the friend is listening for
          incoming connections
        * port (int): Port for the friends listener (0-65535)
        * publicKey (string): friends public key
        * trustLevel (int): How much we trust messages from this friend (0-100%)

    """
    def __init__(self, name="", uid="", address="", port=0, publicKey=0, trustLevel=0):
        self.name = name
        self.address = address
        self.port = port
        self.uid = uid
        self.publicKey = publicKey
        self.trustLevel = trustLevel

    def sendCommand(self, command):
        """send a command message to a friend

        Args:
            * command -- Command object

        """
        logger.debug("attempting to send a command to friend "+self.name)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        cmd = command.toProtocolMessage()
        logger.debug("Message to be sent: "+cmd)
        try:
            logger.debug("trying to connect to "+self.address+":"+str(self.port))
            s.settimeout(10)
            s.connect((self.address, self.port))
            s.send(cmd)
            logger.debug ("Message sent: " + cmd)
        except:
            logger.warning("could not connect to friend "+self.name+" ("+self.address+":"+str(self.port)+")")
        finally:
            s.close()

