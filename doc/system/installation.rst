.. _install:

Installation
************

If packages for your distribution are available use them. If not use the
manual installation described below.

Depencies
=========

fail2ban-p2p depends on the following packages:

 * python
 * python-m2crypt
 * python-argparse

Installation from git
=====================

To checkout the source code from github:
  * git clone https://github.com/mmunz/fail2ban-p2p.git

After the checkout change into the fail2ban directory and install fail2ban-p2p with

# python setup.py install

Installation from tarball
================================

Download the latest release tarball from `Download <download/>`_
and extract it. After changing into the fail2ban-p2p directory execute

# python setup.py install

This will install fail2ban-p2p.py and fail2ban-p2p-client.py to /usr/local/bin.
Modules will be installed to /usr/share/fail2ban-p2p/fail2ban-p2p.

Installation on Debian based systems
====================================

 * Download the latest deb package `Download <download/>`_
 * install depencies: apt-get install python-m2crypt python-argparse
 * install fail2ban-p2p: dpkg -i fail2ban-p2p-<version>.deb
