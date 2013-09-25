# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.

import config
import os
import M2Crypto
import log

c = config.Config()
logger = log.initialize_logging("fail2ban-p2p." + __name__)

def create_keys():
    """Create private/public keypair (RSA 1024 bit)

    If this function is called a private/public keypair is created if it does
    not already exist. If the keypair already exists then the function will
    ask for confirmation to overwrite it. The created keypair will be saved
    in the config directory.
    """

    if os.path.isfile(c.privkey) or os.path.isfile(c.pubkey):
        print "A keypair for this node already exists."
        ask = raw_input('Do you really want to create a new one? [y/N] ')
        if ask != "y":
            return
    M2Crypto.Rand.rand_seed (os.urandom (1024))
    logger.info("Generating a 1024 bit private/public key pair...")
    keypair = M2Crypto.RSA.gen_key (1024, 65537)
    try:
        keypair.save_key(c.privkey, None)
        os.chmod(c.privkey, 0400)
        keypair.save_pub_key(c.pubkey)
        logger.debug("Private key (secret) was saved to " + c.privkey)
        logger.debug("Public key was saved to " + c.pubkey)
    except IOError, e:
        logger.error("Could not save the keypair, check permissions! " + "%s" % e)
	exit()

