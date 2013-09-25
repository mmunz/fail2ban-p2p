.. _configuration:

Configuration
*************

In order to use fail2ban-p2p you need to create a keypair for your node,
exchange public keys with at least one friend and setup fail2ban to work
with fail2ban-p2p.

The default configuration directory is /etc/fail2ban-p2p. You can specify
another directory with the -c command line option. See the CONFIG file in
this directory for a explanation of all config options.

The main configuration file is **fail2ban-p2p.conf**.

The private and public keys are found in this directory, too.

For every friend there is a file in **/etc/fail2ban-p2p/friends/**
with the friends name as filename
(in case you know `tinc <http://www.tinc-vpn.org>`_
you might find this kind of configuration files very familiar).

Configure your node in fail2ban-p2p.conf
========================================

The default location for the main configuration file is
/etc/fail2ban-p2p/fail2ban-p2p.conf. This file contains the configuration
for your node. Following things **must** be configured:

Node - Section
--------------

.. code-block:: python

    [Node]
    name=mynodename
    addresses=127.0.0.1,10.0.0.1
    port=1337
    ownermail=foo@bar.de
    bantime=7200
    threshold=80

+-----------+----------------------------------------------------------+
| parameter | Explanation                                              |
+===========+==========================================================+
| name      | The name of your node. This is only used for             |
|           | informational purposes. In the network nodes are         |
|           | identified by uid (hash of the nodes public key)         |
+-----------+----------------------------------------------------------+
| addresses | A comma seperated list of listen addresses               |
+-----------+----------------------------------------------------------+
| port      | Listening port                                           |
+-----------+----------------------------------------------------------+
| ownermail | Your email address.                                      |
|           | (not used for now, but eventually in the future)         |
+-----------+----------------------------------------------------------+
| bantime   | How long fail2ban-p2p keeps banned hosts in its internal |
|           | database (in seconds)                                    |
+-----------+----------------------------------------------------------+
| treshold  | Minimum trustlevel a received message needs to have to   |
|           | launch an action                                         |
+-----------+----------------------------------------------------------+


Logging - Section
-----------------

.. code-block:: python

    [Logging]
    logfile=/var/log/fail2ban-p2p.log
    loglevel=INFO

+-----------+----------------------------------------------------------+
| parameter | Explanation                                              |
+===========+==========================================================+
| logfile   | The file where logs are written to                       |
|           | (default: /var/log/fail2ban-p2p.log)                     |
+-----------+----------------------------------------------------------+
| loglevel  | Set verbosity level for log output. The following levels |
|           | are defined: DEBUG, INFO, WARN, ERROR, BAN               |
+-----------+----------------------------------------------------------+

Create a keypair for your node and exchange it with friend(s)
=============================================================

If no keypair is found in the configuration directory it will be created
at the first start of fail2ban-p2p.py or when using the -K command line
option. This needs to be done by a user who has write permissions in
the configuration directory.

Two files are created: private.pem and public.pem. private.pem is your
private key, keep this secret. public.pem needs to be shared with at least
one friend. But before you share it add something like this in public.pem
before the key:

.. code-block:: python

    address = 1.2.3.4
    port = 1337
    trustlevel = 80


This is the information how your node is reachable.

+-----------+----------------------------------------------------------+
| parameter | Explanation                                              |
+===========+==========================================================+
| address   | Use your IP address or dns name here.                    |
|           | To listen on all addresses use 0.0.0.0                   |
+-----------+----------------------------------------------------------+
| port      | The port your node listens ons (see fail2ban-p2p.conf)   |
+-----------+----------------------------------------------------------+
| trustlevel| This is something your friend is allowed to editi        |
|           | to give you more or less trust. Its a percentage, so use |
|           | something between 0 and 100.                             |
+-----------+----------------------------------------------------------+

Now send the edited public.pem to your friend(s). For every friend that you
want to add get his private.pem and place it in ``<config dir>/friends``. Rename
the file to the name you want to use for this friend.

Integration with fail2ban
=========================

To properly work and be able to exchange information with the fail2ban-daemon
you need to integrate fail2ban and fail2ban-p2p. Information about attackers
needs to be exchanged in two directions:

From fail2ban-p2p to fail2ban
-----------------------------

Fail2ban gets its information about attackers by watching the fail2ban-p2p
logfile. To setup fail2ban to watch the fail2ban-p2p log file do the following:
 
1. Make fail2ban-p2p log into /var/log/fail2ban-p2p.log (this is the default)
2. Add a jail for fail2ban-p2p like this in /etc/fail2ban/jails.conf:

    .. code-block:: python

        [ssh-p2p]
        enabled = true
        port    = ssh
        filter  = sshd-p2p
        logpath  = /var/log/fail2ban-p2p.log
        bantime = 120
        findtime = 120
        maxretry = 1

  See the fail2ban manual for explanation of these options. You probably
  want to increase the bantime. It is important to leave maxretry at 1 (block
  a host after 1 entry for it was found in /var/log/fail2ban-p2p.log).

3. Add a filter sshd-p2p.conf in /etc/fail2ban/filter.d/sshd-p2p.conf

    .. code-block:: python

       [Definition]
       failregex = ^(.*)BAN(\t)<HOST>*$

From fail2ban to fail2ban-p2p
-----------------------------

1. Setup an action to execute "fail2ban-p2p-client.py -b <ip>" to sent
the attacker IP from fail2ban to fail2ban-p2p.
For an example see doc/fail2ban/action.d/fail2ban-p2p.conf.
You might want to correct the path to client.py and also specify a
configuration directory for fail2ban-p2p with the -c option if you
use a custom config directory.

2. Add this action to a jail, e.g. for the predefined ssh jail in 
/etc/fail2ban/jail.conf:

.. code-block:: python

    [ssh]
    enabled  = true
    port     = ssh
    filter   = sshd
    logpath  = /var/log/auth.log
    action   = iptables[name=SSH, port=ssh, protocol=tcp]
               fail2ban-p2p[name=SSH]
    maxretry = 2

This will ban the offending ip with the iptables action and also send a message
about this attacker to the locally running fail2ban-p2p.

