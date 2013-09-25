#!/usr/bin/python2

# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.

"""
This script can be used to send a ban message to the own node.
To do this it will use the ip address and port given in the configfile
for this node.
"""

import sys
sys.path.insert(1, "./fail2ban-p2p")
sys.path.insert(2, "/usr/share/fail2ban-p2p/fail2ban-p2p")
import config
import hashlib
import os
import argparse
import crypto
import socket
import M2Crypto
from time import time
import json
import util
import version

# Parse arguments
parser = argparse.ArgumentParser(description='fail2ban-p2p-client help.')
parser.add_argument('-b', help='IP address to ban', metavar='IP')
parser.add_argument('-c', default='/etc/fail2ban-p2p/', help='Read configuration from DIR.',
                    metavar='DIR')
parser.add_argument('-d', help='Dump table of blocked hosts in the format <FORMAT> (table, json or count).',
                    metavar='FORMAT')
parser.add_argument('-t', help='The list of blocked hosts should go back that many seconds.',
                    metavar='SECONDS')
parser.add_argument('-q', action='store_true', help='Quiet, no output')
parser.add_argument('-v', action='store_true', help='Verbose output')

args = parser.parse_args()

c = config.Config()
c.configPath = args.c or "/etc/fail2ban-p2p"
c.privkey = os.path.join(c.configPath, 'private.pem')
c.pubkey = os.path.join(c.configPath, 'public.pem')

if c.loadConfig() == False:
    exit()

if not args.d and not args.b:
    print "Please use the -b argument to specify an IP to ban or -d to request information about banned nodes."
    exit()

dump = False

if args.d:
    dump = True;
    if not args.d == "table" and not args.d == "json" and not args.d == "count":
        print("invalid value for -d argument!")
        exit()

timeframe = 3600
if args.t:
    try:
        timeframe = int(args.t)
    except ValueError as e:
        print("Invalid Timeframe specified, only use integers! Using default value of 3600 instead")
        timeframe = 3600

quiet = False
if args.q:
    quiet = True

if dump:
    # Generate a message of type 2 (request to dump list of banned hosts)
    unordered_dict = {
            "msgType": 2,
            "parameter": { "TimeFrame": timeframe},
            "hops": ['local'] 
    }
    serializable_dict = util.sort_recursive(unordered_dict) 

if args.b:
    # Generate a ban message (Type 1)
    unordered_dict = {
            "msgType": 1,
            "parameter": { "Timestamp": int(time()), "AttackerIP": args.b, "Trustlevel": 100 },
            "hops": ['local']
    }
    serializable_dict = util.sort_recursive(unordered_dict) 

if args.b or dump:
    signed_message = json.dumps(serializable_dict)

    SignEVP = M2Crypto.EVP.load_key(c.privkey)
    SignEVP.sign_init()
    SignEVP.sign_update(signed_message)
    StringSignature = SignEVP.sign_final().encode('hex')

    signed_dict = {
        #"protocolVersion": version.protocol,
        "msg": serializable_dict,
        "signature": StringSignature,
	    "protocolVersion": version.protocolVersion
    }
    cmdsigned = json.dumps(signed_dict) 


ret = None

# send message
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((c.addresses[0], int(c.port)))
    s.send(cmdsigned)
    ret = s.recv(1048576) # we need about 50 Bytes per banned node
    if not quiet and args.v:
        print ("Message sent: " + cmdsigned)
except:
    if not quiet:
        print ("could not connect to  "+c.name+" ("+c.addresses[0]+":"+str(c.port)+")")
finally:
    s.close()

if ret: 
    if args.d:
        if "ERROR" in ret:
            print("An error occured:\n")
            print(ret)
        elif args.d == "json":
            print(ret)
        elif args.d == "count":
            print(len(json.loads(ret)))
        else:
            banList = json.loads(ret)
            if len(banList) > 0:
                print("IP".ljust(15, ' ') + "\tTimestamp\t\tBantime\t\tTrustlevel\tStatus")
                for ban in banList:
                    status = "PENDING"
                    if int(c.threshold) <= int(ban['Trustlevel']):
                        status = "BANNED"
                    print(ban['AttackerIP'].ljust(15, ' ') + "\t" + str(ban['Timestamp']) + "\t\t" + str(ban['BanTime']) + "\t\t" + str(ban['Trustlevel'])) + "\t\t" + status
            else:
                print("No hosts in banlist")
    else:
        print("Answer: " + ret)
