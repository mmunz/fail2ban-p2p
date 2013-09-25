# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.


import util
import config
import log
import crypto
import M2Crypto

import json
import util
import version

logger = log.initialize_logging("fail2ban-p2p." + __name__)

class Command:
    '''
    Handle command objects.

    Kwargs:
        * protocolVersion (int): Protocol version number
        * msgType (int): message type
        * parameter (dict): Parameters to send in the message
        * signature (string): The messages signature
        * hops (array): Hops that previously have relayed this message

    '''

    msgType = None
    parameter = ()
    signature = ""
    hops = []

    def __init__(self, protocolVersion=None, msgType=None, parameter={}, signature=None, hops=[]):
        self.msgType = msgType
        self.parameter = parameter
        self.protocolVersion = protocolVersion
        self.signature = signature
        self.hops = hops

    def __string__(self):
        return "Command (msgType = "+str(msgType)+", ...)"

    def toSerializableDict(self):
        '''
        Returns a recursively sorted dictionary 
        '''
        unordered_dict = {
            "msgType": self.msgType,
            "parameter": self.parameter,
            "hops": self.hops
        }
        return util.sort_recursive(unordered_dict)

    def toProtocolMessage(self):
        '''
        Create a JSON-encoded Protocol message.
        '''
        serializable_dict = self.toSerializableDict()

        signed_message = json.dumps(serializable_dict)
        signature = self.sign(signed_message)
        signed_dict = {
            "msg": serializable_dict,
            "signature": signature,
            "protocolVersion": version.protocolVersion
        }
        return json.dumps(signed_dict)

    def sign(self, text):
        """
        Compute signature for a message.

        Args:
            text (string): the json encoded message text.

        Returns:
            A string with the signature for 'text'

        """
        logger.debug("signing outgoing message")
        c = config.Config()

        SignEVP = M2Crypto.EVP.load_key(c.privkey)
        SignEVP.sign_init()
        SignEVP.sign_update(text)
        StringSignature = SignEVP.sign_final().encode('hex')
        logger.debug("Our signature for this message is: " + StringSignature)
        self.signature = StringSignature
        return StringSignature
