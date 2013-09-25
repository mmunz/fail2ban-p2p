# Copyright 2013 Johannes Fuermann <johannes at fuermann.cc>
# Copyright 2013 Manuel Munz <manu at somakoma.de>
#
# This file is part of fail2ban-p2p.
#
# Licensed under the GNU GENERAL PUBLIC LICENSE Version 3. For details
# see the file COPYING or http://www.gnu.org/licenses/gpl-3.0.en.html.

from parser import parse
import log
import customexceptions


logger = log.initialize_logging("fail2ban-p2p." + __name__)


def serve(n, connection, address):
    """Starts the server listener socket to receive messages

    Args:
        * n -- node object
        * connection -- client socket
        * address -- IP address of the node that sent the message

    """

    data = connection.recv(1024)
    logger.debug("Parsing message: " + data)

    command = parse(data)

    if command:
        logger.debug("command syntax verified")
        try:
            n.verifyMessage(command)
            logger.debug("command signature verified")
            n.addMessage(command)
            if command.msgType == 2:
                timeframe = int(command.parameter['TimeFrame'])
                logger.debug("Requested Timeframe is: " + str(timeframe))
                connection.send(n.dumpBanlist(timeframe))
            else:
                connection.send("OK\n")

        except customexceptions.InvalidMessage, e:
            connection.send("ERROR Invalid message\n")
            logger.warn("This message made no sense.")
        except customexceptions.InvalidSignature, e:
            connection.send("ERROR invalid signature\n")
            logger.warn("The Signature could not be verified")
        except customexceptions.InvalidProtocolVersion, e:
            connection.send("ERROR invalid protocol version\n")
    else:
        connection.send("Error\n")
        logger.warn('invalid message')

    connection.close()

    
    #except Exception, e:
        #logger.warn("During the validation of the received message the " +
                    #"exception \"%s\" occured" % (type(e),))
        #logger.debug("The received command was: " + data)
        #connection.send("ERROR\n")
    #finally:
        #connection.close()
