"""
answers.py

A collection of different properties regarding the headers of answers in the protocol.
"""
from struct import calcsize

HEADER_FORMAT = "<BHL"
HEADER_LENGTH = calcsize(HEADER_FORMAT)
