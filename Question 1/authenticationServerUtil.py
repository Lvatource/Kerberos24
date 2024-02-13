"""
authenticationServerUtil.py

A collection of all the authentication server actions, according to the maman instructions.
"""
import constants
import opcodes
from crypto import generate_random_key, generate_encrypted_key_field, generate_ticket
from file import register_client, get_user_key
from interact import parse_payload, create_packet

PROTOCOL_VERSION = 24


def commence_registration(payload: bytes, sock):
    """
    commence_registration(): Register a new user based on the username and password in the payload.

    :param payload: the payload
    :param sock: the connected socket
    """
    print("[*] Registration request received")
    username_bytes, password_bytes = parse_payload(opcodes.REGISTER_CLIENT, payload)
    uid = register_client(username_bytes, password_bytes)
    if uid == constants.FAILED_REGISTRATION_UID:
        sock.sendall(create_packet(None, PROTOCOL_VERSION, opcodes.REGISTRATION_FAILED, 0))
        print("[!] WARNING: Registration failed")
    else:
        sock.sendall(create_packet(None, PROTOCOL_VERSION, opcodes.REGISTRATION_SUCCESSFUL, constants.CLIENT_ID_SIZE, uid))
        print("[*] Registration successful")


def send_sym_key(payload: bytes, sock, client_id: str):
    """
    send_sym_key(): Generate and send a symmetric key and a ticket back to the client.

    :param payload: the payload
    :param sock: the connected socket
    :param client_id: the client id
    """
    print("[*] Shared symmetric key request received")
    server_id_bytes, nonce = parse_payload(opcodes.REQUEST_SYM_KEY, payload)
    shared_key = generate_random_key()
    user_key = get_user_key(client_id)
    if user_key is None:
        sock.sendall(create_packet(None, PROTOCOL_VERSION, opcodes.SERVER_ERROR, 0))
    # Make sure the user exists!
    encrypted_key_field = generate_encrypted_key_field(nonce, shared_key, user_key)
    ticket = generate_ticket(PROTOCOL_VERSION, bytes.fromhex(client_id), server_id_bytes, shared_key)
    if ticket is None:
        sock.sendall(create_packet(None, PROTOCOL_VERSION, opcodes.SERVER_ERROR, 0))
    else:
        sock.sendall(create_packet(None, PROTOCOL_VERSION, opcodes.ANSWER_SYM_KEY,
                                   constants.CLIENT_ID_SIZE + len(encrypted_key_field) + len(ticket), client_id, encrypted_key_field,
                                   ticket))
        print("[*] Shared symmetric key generated and sent successfully")


def answer_invalid_opcode(opcode: int, sock):
    """
    answer_invalid_opcode(): Print an error message for an invalid opcode and send a server error back to the client.

    :param opcode: the opcode
    :param sock: the connected socket
    """
    print("[X] ERROR: Request opcode ", opcode, "is invalid, responding with an error")
    sock.sendall(create_packet(None, PROTOCOL_VERSION, opcodes.SERVER_ERROR, 0))
