"""
interact.py

A collection of function regarding the communication between different agents in the system: creation and parsing of packets
and many helper functions.
"""
import socket
from struct import pack, unpack
import answers
import constants
import opcodes
import requests


def end_connection(sock):
    """
    end_connection(): shut down and close an ongoing socket connection.

    :param sock: the connected socket
    """
    sock.shutdown(socket.SHUT_RDWR)
    sock.close()


def create_payload(opcode: int, *args) -> bytes:
    """
    create_payload(): Creates a payload containing the passed parameters, structured according to the opcode.

    :param opcode: the opcode of the packet
    :param args: all the different fields to be put inside the payload
    :return: The complete payload
    """
    payload = b''
    counter = 0
    if opcode == opcodes.REGISTRATION_FAILED or opcode == opcodes.KEY_ACK or opcode == opcodes.MESSAGE_ACK or opcode == opcodes.SERVER_ERROR:
        pass
    # These packets don't require any payload
    elif opcode == opcodes.REGISTER_CLIENT:
        for arg in args:
            if counter == 0:
                payload += pack('<255s', str.encode(arg))
            elif counter == 1:
                payload += pack('<255s', str.encode(arg))
            else:
                print("[X] ERROR: Received too many arguments for the payload creation, terminating")
                exit(1)
            counter += 1
            # Build according to the maman instructions
    elif opcode == opcodes.REGISTRATION_SUCCESSFUL:
        for arg in args:
            if counter == 0:
                payload += pack('<16s', arg)
            else:
                print("[X] ERROR: Received too many arguments for the payload creation, terminating")
                exit(1)
            counter += 1
            # Build according to the maman instructions
    elif opcode == opcodes.REQUEST_SYM_KEY:
        for arg in args:
            if counter == 0:
                server_id = bytes.fromhex(arg)
                payload += pack('<16s', server_id)
            elif counter == 1:
                payload += pack('<8s', arg)
            else:
                print("[X] ERROR: Received too many arguments for the payload creation, terminating")
                exit(1)
            counter += 1
            # Build according to the maman instructions
    elif opcode == opcodes.ANSWER_SYM_KEY:
        for arg in args:
            if counter == 0:
                client_id = bytes.fromhex(arg)
                payload += pack('<16s', client_id)
            elif counter == 1:
                payload += arg
            elif counter == 2:
                payload += arg
            else:
                print("[X] ERROR: Received too many arguments for the payload creation, terminating")
                exit(1)
            counter += 1
            # Build according to the maman instructions
    elif opcode == opcodes.SEND_SYM_KEY:
        for arg in args:
            if counter == 0:
                payload += arg
            elif counter == 1:
                payload += arg
            else:
                print("[X] ERROR: Received too many arguments for the payload creation, terminating")
                exit(1)
            counter += 1
            # Build according to the maman instructions
    elif opcode == opcodes.SEND_MESSAGE:
        for arg in args:
            if counter == 0:
                payload += pack('<I', arg)
            elif counter == 1:
                payload += pack('<16s', arg)
            elif counter == 2:
                payload += pack('<{}s'.format(len(arg)), arg)
            else:
                print("[X] ERROR: Received too many arguments for the payload creation, terminating")
                exit(1)
            counter += 1
            # Build according to the maman instructions
    else:
        print("[X] ERROR: Opcode", opcode, "is not valid, terminating")
        exit(1)
        # If the opcode isn't valid, terminate
    return payload


def create_packet(client_id, version: int, opcode: int, payload_size: int, *args) -> bytes:
    """
    create_packet(): creates a packet containing the passed parameters, structured according to the opcode.

    :param client_id: the client uuid
    :param version: the sender version
    :param opcode: the opcode
    :param payload_size: the size of the payload
    :param args: all the different fields that will be put in the payload
    :return: the complete packet
    """
    if client_id is not None:
        client_id = bytes.fromhex(client_id)
        # Convert the client_id string into bytes
    if opcode == opcodes.REGISTER_CLIENT:
        header = pack(requests.HEADER_FORMAT, client_id, version, opcode, payload_size)
    elif opcode == opcodes.REQUEST_SYM_KEY:
        header = pack(requests.HEADER_FORMAT, client_id, version, opcode, payload_size)
    elif opcode == opcodes.REGISTRATION_SUCCESSFUL:
        header = pack(answers.HEADER_FORMAT, version, opcode, payload_size)
    elif opcode == opcodes.REGISTRATION_FAILED:
        header = pack(answers.HEADER_FORMAT, version, opcode, payload_size)
    elif opcode == opcodes.ANSWER_SYM_KEY:
        header = pack(answers.HEADER_FORMAT, version, opcode, payload_size)
    elif opcode == opcodes.SEND_SYM_KEY:
        header = pack(requests.HEADER_FORMAT, client_id, version, opcode, payload_size)
    elif opcode == opcodes.KEY_ACK:
        header = pack(answers.HEADER_FORMAT, version, opcode, payload_size)
    elif opcode == opcodes.MESSAGE_ACK:
        header = pack(answers.HEADER_FORMAT, version, opcode, payload_size)
    elif opcode == opcodes.SEND_MESSAGE:
        header = pack(requests.HEADER_FORMAT, client_id, version, opcode, payload_size)
    elif opcode == opcodes.SERVER_ERROR:
        header = pack(answers.HEADER_FORMAT, version, opcode, payload_size)
    else:
        print("[X] ERROR: Opcode", opcode, "is not valid, terminating")
        exit(1)
        # If the opcode isn't valid, terminate
    packet = header + create_payload(opcode, *args)
    # Call the create_payload() function to complete the process
    return packet


def parse_request_header(header: bytes) -> (str, int, int, int):
    """
    parse_request_header(): parses a request packet header and returns the separate fields.

    :param header: the header
    :return: the separate header fields
    """
    client_id, version, opcode, payload_size = unpack(requests.HEADER_FORMAT, header)
    return client_id.hex(), version, opcode, payload_size


def parse_answer_header(header: bytes) -> (int, int, int):
    """
    parse_answer_header(): parses an answer packet header and returns the separate fields.

    :param header: the packet
    :return: the separate header fields
    """
    version, opcode, payload_size = unpack(answers.HEADER_FORMAT, header)
    return version, opcode, payload_size


def parse_payload(opcode: int, payload: bytes) -> bytes:
    """
    parse_payload(): parses a packet payload and returns the fields according to the opcode.

    :param opcode: the packet opcode
    :param payload: the packet payload
    :return: the payload fields
    """
    if opcode == opcodes.REGISTRATION_SUCCESSFUL:
        parsed_payload = unpack("<16s", payload)[0].hex()
    elif opcode == opcodes.REQUEST_SYM_KEY:
        parsed_payload = unpack("<16s8s", payload)
    elif opcode == opcodes.ANSWER_SYM_KEY:
        parsed_payload = unpack("<16s16s48s", get_encrypted_key_field_from_payload(payload))
    elif opcode == opcodes.SEND_SYM_KEY:
        parsed_payload = (unpack("<16s16s32s32s16s", get_authenticator_from_payload(payload)),
                          unpack("<1B16s16s8s16s48s16s", get_ticket_from_payload(payload)))
        # Here we parse both the authenticator and the ticket, hence the double unpack
    elif opcode == opcodes.SEND_MESSAGE:
        parsed_payload = unpack("<I16s", get_message_size_and_iv(payload))
    elif opcode == opcodes.REGISTER_CLIENT:
        parsed_payload = unpack("<255s255s", payload)
    else:
        print("[X] ERROR: Opcode " + str(opcode) + " is not valid")
        parsed_payload = None
    return parsed_payload


def get_ticket_from_payload(packet: bytes) -> bytes:
    """
    get_ticket_from_payload(): returns the ticket within the packet.

    :param packet: the packet
    :return: the ticket
    """
    return packet[-constants.TICKET_SIZE:]


def get_encrypted_key_field_from_payload(payload: bytes) -> bytes:
    """
    get_encrypted_key_field_from_payload(): returns the encrypted key portion from the payload.

    :param payload: the payload
    :return: the encrypted key portion
    """
    return payload[constants.CLIENT_ID_SIZE:constants.ENCRYPTED_KEY_FIELD_SIZE + constants.CLIENT_ID_SIZE]


def get_authenticator_from_payload(payload: bytes) -> bytes:
    """
    get_authenticator_from_payload(): returns the authenticator within the payload.

    :param payload: the payload
    :return: the authenticator
    """
    return payload[:constants.AUTHENTICATOR_SIZE]


def get_message_size_and_iv(payload: bytes) -> bytes:
    """
    get_message_size_and_iv(): returns the size and iv portion from the payload.

    :param payload: the payload
    :return: the size and iv portion
    """
    return payload[:constants.MESSAGE_SIZE_FIELD_SIZE + constants.IV_FIELD_SIZE]


def get_encrypted_message(payload: bytes, size: int) -> bytes:
    """
    get_encrypted_message(): returns the encrypted message within the payload.

    :param payload: the payload
    :param size: the size of the encrypted message
    :return: the encrypted message
    """
    return payload[-size:]
