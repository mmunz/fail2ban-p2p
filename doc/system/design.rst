Design
******

.. _design:

How messages are distributed
============================

.. image:: ./images/message-propagation.png
    :align: left

**Legend**


  * grey dotted: bidirectional connection between nodes (both can send messages to each other)
  * red: Brute Force to Node A
  * blue: Brute Force to Node B 

**Explanation**

Every node in this Graph uses a Trustlevel of 80% (which is the default for fail2ban-p2p) and also uses a Treshold of 80%. That means: Only if we get a message with a Trustlevel which is equal or higher than the Treshold the attacker is blocked.

**First: Attacker brute forces Node A (red)**

Fail2ban on Node A detects that the attacker had to many failed logins. It now blocks the attackers IP (1.2.3.4) locally and also sends a message to the local fail2ban-p2p node. fail2ban-p2p now distributes this attacker information to its friends Node B and Node C, both accept it with a Trustlevel of 80%. Because this is equal to the Treshold value B and C now also block this attacker. Node C also sends this message to its two other friends D and E. But D and E give the message from C now only a Trustlevel of 64% (80%*80%), they don't block that attacker (yet), but would redistribute the message to their friends again and save the information about this attacker in their internal database.

**Second: Attacker now also brute forces Node B (blue)**

This time Fail2ban on Node B detects the brute force and blocks the attacker (in fact it is already blocked, but forget that for this example). It now sends this attacker information to Node A which already knows about the attacker and already blocked it. But it redistributes the message to its friend C again. Because the node which detected the attack (Node B) is 1 hop away Node C now gives this attacker information a Trustvalue of 64% and add this to the Trustvalue of 80% it already have. trust cannot be more than 100%, so node C now updates its internal database and stores 100% trustvalue for the attacker. It also retransmits the attacker info to Nodes D and E. Bot give this message a Trustvalue of 51,2% now (80%*80%*80%) which is again added to the Trustvalue of 64% it had before for that attacker IP and again it cuts it at 100%. Finally the attackers IP is now also blocked on Nodes D and E. 


.. _message_types:

Message Types for fail2ban-p2p
==============================

All messages are exchanged in JSON formatted strings. The following message types are
definded:

Type 1: Attack message
----------------------

This message type is used to notify friends about the IP of an attacker.

**Mandatory parameters:** AttackerIP, Timestamp

.. code-block:: javascript

    {
        "msg": {
            "hops": [
                "hop1",
                "hop2"
            ],
            "msgType": 1,
            "parameter": {
                "AttackerIP": "1.2.3.4",
                "Timestamp": "1363279754",
                "Trustlevel": "80"
            },
        },
        "protocolVersion": 2
        "signature": "foo"
    }

Type 2: Dumprequest / Direct output
-----------------------------------

Message send to neighbors to request a dump of all known attackmessages
for a given Timeframe. Will return a json encoded list of all banned ips.

**Mandatory parameters:** TimeFrame

.. code-block:: javascript

    {
        "msg": {
            "hops": [
                "local"
            ],
            "msgType": 2,
            "parameter": {
                "TimeFrame": "3600"
            },
        },
        "protocolVersion": 2
        "signature": "foo"
    }

Type 3: Dumprequest / Send normal ban messages to sender of this message
------------------------------------------------------------------------

Message send to friend to trigger sending ban messages for all ips in
banlist for a given Timeframe. This can be used to pull banlists when a node
is started up.

**Mandatory parameters:** TimeFrame

.. code-block:: javascript

    {
        "msg": {
            "hops": [
                "local"
            ],
            "msgType": 3,
            "parameter": {
                "TimeFrame": "3600"
            },
        },
        "protocolVersion": 2
        "signature": "foo"
    }

