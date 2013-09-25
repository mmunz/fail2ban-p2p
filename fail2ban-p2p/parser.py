# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.

import command
import re
import log
import pdb

import json

# constants for length of RELEASE and MSGTYPE
logger = log.initialize_logging("fail2ban-p2p." + __name__)

def getDictValue(dict, key):
    """Get a value from a dict.

    Args:
        * dict: The dictionary to get the value from
        * key: Key of the value to fetch

    Returns:
        Corresponding value if the key exists or False.

    """

    try:
        return dict[key]
    except KeyError, e:
        return False
            
def parse(msg):
    """Parse a protocol message to a command object.

    Args:
        * msg -- the received message string

    Returns:
       command object

    """
 
    logger.debug("parsing message...")
    signed_dict = False

    try:
        signed_dict = json.loads(msg)
    except ValueError, e:
        logger.warning("The received message does not appear to be valid json.")
        return False

    if signed_dict:
        message_dict = getDictValue(signed_dict, 'msg')
        msg = command.Command()

        msg.signature = getDictValue(signed_dict, 'signature')
        msg.protocolVersion = getDictValue(signed_dict, 'protocolVersion')
        msg.msgType = getDictValue(message_dict, 'msgType')
        msg.parameter = getDictValue(message_dict, 'parameter')
        msg.hops = getDictValue(message_dict, 'hops')
        return msg
