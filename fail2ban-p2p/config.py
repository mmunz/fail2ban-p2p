# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.

import ConfigParser
import os
import logging

class Config:
    """
    Handles config file loading and parsing of config values,
    uses borg pattern
    """
    __shared_state = {}

    configPath = ""
    configFile = ""
    logFile = ""
    logLevel = ""
    addresses = []
    name = ""
    port = 0
    ownermail = ""
    banTime = 0
    threshold = 0    

    def __init__(self, configPath = '/etc/fail2ban-p2p'):
	self.__dict__ = self.__shared_state # borg pattern.

    def loadConfig(self):
        """
        Load and parse the config file
        """
        def get_option(section, option, mandatory, default):
            '''Gets an option from the config file

            Args:
                section: Section in config file
                option: option in config file
                default: the default value if option was not found
                mandatory: if this option is mandatory
            Returns:
                The value of the option we requested or the default value if the
                option is not mandatory; else False
            '''
            try:
                value = config.get(section, option)
            except (ConfigParser.NoOptionError, ConfigParser.NoSectionError):
                if mandatory:
                    print  "Mandatory option " + option + " not found in config file " + self.configFile
                    return False
                else:
                    value = default
            return value

        config = ConfigParser.RawConfigParser()
        self.configFile = os.path.join(self.configPath, 'fail2ban-p2p.conf')

        if os.access(self.configFile, os.R_OK):
            config.read(self.configFile)
            self.logFile = get_option('Logging', 'logfile', False, '/var/log/fail2ban-p2p.log')
            self.logLevel = get_option('Logging', 'loglevel', False, 'DEBUG')
            self.logLevel = eval("logging." + self.logLevel) or 10
            self.addresses = get_option('Node', 'addresses', False, '0.0.0.0')
            self.addresses = [a.strip() for a in self.addresses.split(',')]
            self.name = get_option('Node', 'name', False, 'Ididnotsetaname')
            self.port = get_option('Node', 'port', False, 1337)
            self.banTime = get_option('Node', 'bantime', False, 7200)
            self.ownermail = get_option('Node', 'ownermail', False, "ididnotsetmyemail@example.org")
            self.threshold = get_option('Node', 'threshold', False, 80)
            
        else:
            print('ERROR: Configuration directory "'  + self.configPath + '" does not exist.\n' +
                  'Please create a configuration or specify another valid configuration directory with the "-c" argument.')
            return False
