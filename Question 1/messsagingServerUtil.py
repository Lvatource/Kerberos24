"""
messagingServerUtil.py

A collection of all the messaging server actions, according to the maman instructions.
"""
from struct import unpack
import opcodes
from crypto import b64_key_decrypt, decrypt_aes_cbc
from interact import parse_payload, create_packet, get_encrypted_message
import time

SERVER_VERSION = 24


def receive_sym_key(payload: bytes, sock, client_id: str, tickets: dict):
    """
    receive_sym_key(): Receives a ticket and authenticator, check their validity and stores.

    :param payload: the payload containing the ticket and authenticator
    :param sock: the connected socket
    :param client_id: the client id
    :param tickets: the dictionary holding all the different tickets
    """
    print("[*] Shared symmetrical key received")
    try:
        f = open('msg.info')
        print("[*] msg.info found")
        f.readline()
        f.readline()
        server_id = f.readline()
        base64_sym_key = f.readline()
        f.close()
    except FileNotFoundError:
        print("[X] ERROR: msg.info not found, terminating")
        exit(1)
        # Acquire the server key from the msg.info file
    msg_key = b64_key_decrypt(base64_sym_key)
    authenticator, ticket = parse_payload(opcodes.SEND_SYM_KEY, payload)
    shared_key = decrypt_aes_cbc(ticket[5], msg_key, ticket[4])
    expiration_bytes = decrypt_aes_cbc(ticket[6], msg_key, ticket[4])
    expiration_time = int.from_bytes(expiration_bytes, byteorder="little")
    if is_expired(expiration_time):
        print("[X] ERROR: Expiration time for the ticket has exceeded, responding with an error")
        sock.sendall(create_packet(None, SERVER_VERSION, opcodes.SERVER_ERROR, 0))
        # Check if the ticket is already expired
    else:
        decrypted_version = unpack("<B", decrypt_aes_cbc(authenticator[1], shared_key, authenticator[0]))[0]
        decrypted_client_id = decrypt_aes_cbc(authenticator[2], shared_key, authenticator[0])
        decrypted_server_id = decrypt_aes_cbc(authenticator[3], shared_key, authenticator[0])
        if decrypted_version != ticket[0] or decrypted_client_id != ticket[1] or decrypted_server_id != ticket[
            2] or decrypted_client_id != bytes.fromhex(client_id) or decrypted_server_id != bytes.fromhex(
            server_id):
            print("[X] Data discrepancy detected, responding with an error")
            sock.sendall(create_packet(None, SERVER_VERSION, opcodes.SERVER_ERROR, 0))
            # Check the integrity of the data
        else:
            save_ticket(tickets, client_id, shared_key, expiration_time, sock)


def save_ticket(tickets: dict, client_id: str, shared_key: bytes, expiration_time: int, sock):
    """
    save_ticket(): Store the shared key and the expiration time in the 'tickets' dictionary.

    :param tickets: the dictionary holding all the different tickets
    :param client_id: the client id
    :param shared_key: the shared symmetrical
    :param expiration_time: the expiration time
    :param sock: the connected socket
    """
    tickets[client_id] = (shared_key, expiration_time)
    print("[*] User " + client_id + "'s ticket has been added to RAM")
    sock.sendall(create_packet(None, SERVER_VERSION, opcodes.KEY_ACK, 0))
    print("[*] Shared symmetrical key received successfully")


def receive_message(payload: bytes, sock, client_id: str, tickets: dict):
    """
    receive_message(): Parses an incoming message from the payload using the ticket associated with passed client id, and prints it.

    :param payload: the payload
    :param sock: the connected socket
    :param client_id: the client id
    :param tickets: the dictionary holding all the different tickets
    """
    print("[*] Message request received")
    if client_id not in tickets:
        print("[!] WARNING: Client", client_id,
              "hasn't acquired the appropriate ticket, responding with an error")
        sock.sendall(create_packet(None, SERVER_VERSION, opcodes.SERVER_ERROR, 0))
        # Find the client's ticket
    else:
        if is_expired(get_client_ticket_expiration(client_id, tickets)):
            print("[!] WARNING: Expiration time for the ticket has exceeded, responding with an error")
            sock.sendall(create_packet(None, SERVER_VERSION, opcodes.SERVER_ERROR, 0))
            # Check if the ticket is still valid
            # Decided not to delete even if expired, as now we can use the dict as a "last-seen" database
        else:
            msg_size, msg_iv = parse_payload(opcodes.SEND_MESSAGE, payload)
            encrypted_msg = get_encrypted_message(payload, msg_size)
            encrypted_msg = unpack('<{}s'.format(len(encrypted_msg)), encrypted_msg)[0]
            decrypted_msg = decrypt_aes_cbc(encrypted_msg, get_client_shared_key(client_id, tickets), msg_iv).decode(
                "utf-8")
            print("[@] Client", client_id, "says:", decrypted_msg)
            # Print the received message to the console
            sock.sendall(create_packet(None, SERVER_VERSION, opcodes.MESSAGE_ACK, 0))


def is_expired(expiration_time: int) -> bool:
    """
    is_expired(): Checks whether a certain time has passed.

    :param expiration_time: the time in question
    :return: True if it did, False otherwise.
    """
    now = int(time.time())
    return now > expiration_time


def get_client_shared_key(client_id: str, tickets: dict) -> bytes:
    """
    get_client_shared_key(): Returns the shared key associated with the passed client id.

    :param client_id: the client id
    :param tickets: the dictionary holding all the different tickets
    :return: the shared key
    """
    return tickets[client_id][0]


def get_client_ticket_expiration(client_id: str, tickets: dict) -> int:
    """
    get_client_ticket_expiration(): Returns the expiration time of the ticket associated with the passed client id.

    :param client_id: the client id
    :param tickets: the dictionary holding all the different tickets
    :return: the ticket expiration time
    """
    return tickets[client_id][1]


def answer_invalid_opcode(opcode: int, sock):
    """
    answer_invalid_opcode(): Print an error message for an invalid opcode and send a server error back to the client.

    :param opcode: the opcode
    :param sock: the connected socket
    """
    print("[X] ERROR: Request opcode ", opcode, "is invalid, responding with an error")
    sock.sendall(create_packet(None, SERVER_VERSION, opcodes.SERVER_ERROR, 0))
