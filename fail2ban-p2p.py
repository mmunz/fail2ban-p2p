#!/usr/bin/python2

# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.

# Main program for fail2ban-p2p.

# set lib paths
import sys
sys.path.insert(1, "./fail2ban-p2p")
sys.path.insert(2, "/usr/share/fail2ban-p2p/fail2ban-p2p")
import config
import node
import log
import os
import argparse
import crypto

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='fail2ban-p2p help.')
    parser.add_argument('-K', action='store_true', help='Create private/public keypair')
    parser.add_argument('-c', default='/etc/fail2ban-p2p/', help='Read configuration from DIR.',
                        metavar='DIR')
    args = parser.parse_args()

    c = config.Config()
    c.configPath = args.c or "/etc/fail2ban-p2p"
    c.privkey = os.path.join(c.configPath, 'private.pem')
    c.pubkey = os.path.join(c.configPath, 'public.pem')

    if c.loadConfig() == False:
        raise OSError #, 'Config error, check log.'

    logger = log.initialize_logging("fail2ban-p2p")

    if args.K:
        crypto.create_keys()
        exit()
    # make sure the keys exist
    if not os.path.isfile(c.privkey) or not os.path.isfile(c.pubkey):
        logger.warning('Private or public key not found, creating them')
        crypto.create_keys()

    n = None
    try:
        n = node.Node()
        n.loadConfig()
        n.getFriends()
        n.requestBanlist()
        n.cleanBanlist()
        n.openSocket()
    except (KeyboardInterrupt):
        logger.info("Keyboard Interrupt received, going down")
        n.cleanBanlistStop()
        n.closeSocket()
        logger.info("kthxbai!")

