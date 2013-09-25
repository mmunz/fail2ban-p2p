"""
Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
Copyright 2013 Manuel Munz <manu at somakoma.de>

This file is part of fail2ban-p2p.

Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.
"""

"""
This script can be used to send a ban message to the own node.
To do this it will use the ip address and port given in the configfile
for this node.
"""

from distutils.core import setup
from os.path import isfile, join, isdir
import sys
from sys import argv
from glob import glob
sys.path.insert(1, "./fail2ban-p2p")
from version import version

longdesc = '''
Fail2Ban-P2P can be used to exchange information
about attackers between different hosts that are
running fail2ban in a P2P/F2F network.
'''


setup(
    name = "fail2ban-p2p",
    #version = version,
    description = "exchange fail2ban attacker info between hosts using P2P",
    long_description = longdesc,
    version = version,
    author = "Johannes Fuermann, Manuel Munz",
    author_email = "foo@bar.xyz",
    url = "https://svn.physik.uni-augsburg.de/projects/fail2ban-p2p",
    license = "GPL",
    platforms = "Posix",
    scripts = [
        'fail2ban-p2p.py',
        'fail2ban-p2p-client.py'
    ],
    packages = [
        'fail2ban-p2p'
    ],
    data_files = [
        ('/etc/fail2ban-p2p', glob("config/*.conf")),
        ('/etc/fail2ban-p2p/friends', glob('config/friends/*'))
    ]
)

# Update config file
if argv[1] == "install":
        print
        print "Please do not forget to update your configuration files."
        print "They are in /etc/fail2ban-p2p/."
        print


