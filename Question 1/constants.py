"""
constants.py

A collection of all the constants essential for the system.
"""
from Crypto.Cipher import AES
import requests

DEFAULT_PORT = 1256
MAX_USERNAME_LENGTH = 254
MAX_PASSWORD_LENGTH = 254
MAX_SERVER_NAME_LENGTH = 255
NO_CLIENT_ID = '00000000000000000000000000000000'
SINGLE_MESSAGE_SERVER_ID = '00000000000000000000000000000000'
CLIENT_REGISTRATION_PAYLOAD_SIZE = 255 + 255
MAX_PACKET_LENGTH = requests.HEADER_LENGTH + 4 + 16 + (2 ** 8) ** 4  # Packet containing the largest message (a bit more
# than 4gb of data)
MAX_MESSAGE_LENGTH = (2**8)**4-AES.block_size
FAILED_REGISTRATION_UID = -1
TICKET_SIZE = 1+16+16+8+16+48+16
AUTHENTICATOR_SIZE= 16+16+32+32+16
ENCRYPTED_KEY_FIELD_SIZE = 16+16+48
CLIENT_ID_SIZE = 16
IV_FIELD_SIZE = 16
EXPIRATION_TIME = 5*60  # Represented in seconds
TIME_FIELD_SIZE = 8
KEY_SIZE = 32
NONCE_SIZE = 8
MESSAGE_SIZE_FIELD_SIZE = 4
TIME_FORMAT = "%d-%m-%y, %H.%M.%S\n"