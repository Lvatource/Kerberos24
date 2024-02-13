"""
requests.py

A collection of different properties regarding the headers of requests in the protocol.
"""
from struct import calcsize

HEADER_FORMAT = "<16sBHL"
HEADER_LENGTH = calcsize(HEADER_FORMAT)
