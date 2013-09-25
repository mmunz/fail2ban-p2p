# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.

import config
import logging
import sys
import os
from logging.handlers import WatchedFileHandler

def initialize_logging(name="unknown"):
    """Initializes the logging module.

    This initializes pythons logging module:

        * set loglevel (from nodes config)
        * set logfile
        * define new loglevel BAN with priority 90
        * format log messages
        * log to file as well as stderr

    Kwargs:
        name (string): name of the module initializing the logger

    """
    c = config.Config()
    if not c.logLevel:
        c.logLevel = logging.DEBUG
    if not c.logFile:
        c.logFile = "/dev/null"

    logging.BAN = 90
    logging.addLevelName(logging.BAN, 'BAN')
    logger = logging.getLogger(name)
    logger.ban = lambda msg, *args: logger._log(logging.BAN, msg, args)

    formatter = logging.Formatter('%(asctime)s - %(name)s\t%(levelname)s\t%(message)s')
    logger.setLevel(c.logLevel)
    if name == "fail2ban-p2p": # Only add new handlers when called from main.py
        try:
            log2file = WatchedFileHandler(c.logFile)
            log2file.setFormatter(formatter)
            log2file.setLevel(c.logLevel)
            logger.addHandler(log2file)
        except:
            print("--- WARNING --- LOGFILE " + c.logFile + " IS EITHER NONEXISTENT OR NOT WRITABLE") 
        log2stderr = logging.StreamHandler(sys.stderr)
        log2stderr.setFormatter(formatter)
        log2stderr.setLevel(c.logLevel)
        logger.addHandler(log2stderr)
    return logger
