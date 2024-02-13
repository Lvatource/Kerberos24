"""
opcodes.py

A collection of all the different opcodes utilized throughout the protocol, with their according values.
"""
#################################
# Client -> Auth                #
REGISTER_CLIENT = 1024          #
REQUEST_SYM_KEY = 1027          #
#################################
# Client -> Message             #
SEND_SYM_KEY = 1028             #
SEND_MESSAGE = 1029             #
#################################
# Auth -> Client                #
REGISTRATION_SUCCESSFUL = 1600  #
REGISTRATION_FAILED = 1601      #
ANSWER_SYM_KEY = 1603           #
#################################
# Message -> Client             #
KEY_ACK = 1604                  #
MESSAGE_ACK = 1605              #
#################################
# Servers -> Client             #
SERVER_ERROR = 1609             #
#################################
