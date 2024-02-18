"""
clientUtil.py

A collection of all the different actions the client is tasked with doing- registering, requesting a symmetrical key,
sending the symmetrical key and sending messages.
"""
import socket

import answers
import constants
import opcodes
from crypto import generate_random_iv, encrypt_aes_cbc, generate_random_nonce, get_password_SHA256_digest, \
    decrypt_aes_cbc, generate_authenticator
from file import validate_password, validate_username, get_null_terminated_string
from interact import create_packet, parse_answer_header, end_connection, parse_payload, get_ticket_from_payload

CLIENT_VERSION = 24


def send_message(shared_key: bytes, client_id: str, sock: socket.socket):
    """
    send_message(): sends a message to the message server

    :param shared_key: the shared symmetrical key
    :param client_id: the uuid of the client
    :param sock: the connected socket
    """
    message = input("[#] Enter your desired message: ")
    while len(message.encode("utf-8")) > constants.MAX_MESSAGE_LENGTH:
        message = input("[!] WARNING: Input size it too big- the message can be up to 4gb, please try again")
        # Make sure the message is not too big
    msg_iv = generate_random_iv()
    encrypted_message = encrypt_aes_cbc(message.encode("utf-8"), shared_key, msg_iv)
    msg_size = len(encrypted_message)
    sock.sendall(
        create_packet(client_id, CLIENT_VERSION, opcodes.SEND_MESSAGE, constants.MESSAGE_SIZE_FIELD_SIZE + len(msg_iv) + msg_size, msg_size,
                      msg_iv, encrypted_message))
    # Send the message to the message server
    header = sock.recv(answers.HEADER_LENGTH)
    version, opcode, payload_size = parse_answer_header(header)
    if opcode == opcodes.MESSAGE_ACK:
        print("[*] The printing has been completed successfully")
    elif opcode == opcodes.SERVER_ERROR:
        print("[X] ERROR: Message server responded with an error")
        end_connection(sock)
        exit(1)
    else:
        print("[X] ERROR: Received an incompatible opcode, terminating")
        end_connection(sock)
        exit(1)


def log_in() -> str:
    """
    log_in(): Gains the client id by either reading from the me.info file or registering.

    :return: the client id
    """
    try:
        f = open('me.info')
        print("[*] me.info found")
        f.close()
    # First, make sure if the me.info file exists
    except FileNotFoundError:
        # In case me.info doesn't exist, we register
        print("[*] me.info file not found, commencing registration")
        username = input("[#] Enter your username: ")
        while not validate_username(username):
            print("[!] WARNING: Entered username is invalid- the username must be up to", constants.MAX_USERNAME_LENGTH,
                  " characters (at least 1 character) and can't contain \':\', please try again")
            username = input("[#] Enter your new username: ")
        # Make sure the username is not too long and that it doesn't include ":"
        username += '\0'
        password = input("[#] Enter your password: ")
        while not validate_password(password):
            print("[!] WARNING: Entered password is invalid- the password must be up to", constants.MAX_PASSWORD_LENGTH,
                  "characters (at least 1 character), please try again")
            password = input("[#] Enter your new password: ")
        # Make sure the password is not too long
        password += '\0'
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            try:
                f = open('srv.info')
                print("[*] Reading ip:port(s) from srv.info")
                data = f.readline()
                auth_ip_address, auth_port = data.split(":")
                auth_port = auth_port[:-1]
                f.close()
                # Find the ip address and port from the srv.info
            except FileNotFoundError:
                print("[X] ERROR: srv.info doesn't exist, terminating")
                exit(1)
            sock.connect((auth_ip_address, int(auth_port)))
            sock.sendall(create_packet(constants.NO_CLIENT_ID, CLIENT_VERSION,
                                       opcodes.REGISTER_CLIENT, constants.CLIENT_REGISTRATION_PAYLOAD_SIZE,
                                       username, password))
            # Registration packet sent
            header = sock.recv(answers.HEADER_LENGTH)
            version, opcode, payload_size = parse_answer_header(header)
            payload = sock.recv(payload_size)
            if opcode == opcodes.REGISTRATION_SUCCESSFUL:
                print("[*] Registration successful, saving data into me.info for later use")
                uid = parse_payload(opcode, payload)
                f = open('me.info', 'a')
                f.write(get_null_terminated_string(username) + '\n')
                f.write(uid)
                f.close()
            elif opcode == opcodes.REGISTRATION_FAILED:
                print("[X] ERROR: Username is already taken, terminating")
                end_connection(sock)
                exit(1)
            elif opcode == opcodes.SERVER_ERROR:
                print("[X] ERROR: Server responded with an unexpected error, terminating")
                end_connection(sock)
                exit(1)
            else:
                print("[X] ERROR: Received an incompatible opcode, terminating")
                end_connection(sock)
                exit(1)
            end_connection(sock)
    f = open('me.info')
    # We read out the client id from the file that now surely exists
    username = f.readline()
    if not validate_username(username):
        print("[X] ERROR: Client username in me.info is invalid, please create a new account. Terminating")
        exit(1)
        # We make sure the username written in the file is valid as well, otherwise we terminate
    client_id = f.readline()
    f.close()
    return client_id


def establish_connection(client_id: str) -> (bytes, socket.socket):
    """
    establish_connection(): establishes a connection between the client and the message server

    :param client_id: the client uuid
    :return: the shared symmetrical key and the connected socket
    """
    try:
        f = open('srv.info')
        print("[*] Reading ip:port(s) from srv.info")
        data = f.readline()
        auth_ip_address, auth_port = data.split(":")
        auth_port = auth_port[:-1]
        data = f.readline()
        message_ip_address, message_port = data.split(":")
        f.close()
        # Find the ip address and port of the server from the srv.info file
    except FileNotFoundError:
        print("[X] ERROR: srv.info doesn't exist, terminating")
        exit(1)
        # If it doesn't exist, terminate
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.connect((auth_ip_address, int(auth_port)))
        nonce = generate_random_nonce()
        sock.sendall(create_packet(client_id, CLIENT_VERSION, opcodes.REQUEST_SYM_KEY, len(constants.SINGLE_MESSAGE_SERVER_ID) + len(nonce),
                                   constants.SINGLE_MESSAGE_SERVER_ID, nonce))
        header = sock.recv(answers.HEADER_LENGTH)
        version, opcode, payload_size = parse_answer_header(header)
        payload = sock.recv(payload_size)
        end_connection(sock)
        # Request a symmetrical key (and a ticket) from the authentication server
    password = input("[#] Enter your password: ")
    # Ask for user password in order to decrypt the encrypted key field
    user_key = get_password_SHA256_digest(password).digest()
    encrypted_key_iv, encrypted_nonce, encrypted_shared_key = parse_payload(opcode, payload)
    received_nonce = decrypt_aes_cbc(encrypted_nonce, user_key, encrypted_key_iv)
    if nonce != received_nonce:
        print("[X] ERROR: Nonce has been compromised, wrong password / a reply attack is possible. Terminating")
        exit(1)
    # If the nonce was changed, terminate
    print("[*] Nonce has been confirmed, continuing...")
    shared_key = decrypt_aes_cbc(encrypted_shared_key, user_key, encrypted_key_iv)
    if shared_key is None:
        print("[X] Error: Decryption failed for shared key, terminating")
        exit(1)
    ticket = get_ticket_from_payload(payload)
    client_id_bytes = bytes.fromhex(client_id)
    server_id_bytes = bytes.fromhex(constants.SINGLE_MESSAGE_SERVER_ID)
    authenticator = generate_authenticator(version, client_id_bytes, server_id_bytes, shared_key)
    # Generate an authenticator
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.connect((message_ip_address, int(message_port)))
    sock.sendall(
        create_packet(client_id, CLIENT_VERSION, opcodes.SEND_SYM_KEY, len(authenticator) + len(ticket),
                      authenticator, ticket))
    # Send the ticket and the authenticator to the message server
    header = sock.recv(answers.HEADER_LENGTH)
    version, opcode, payload_size = parse_answer_header(header)
    if opcode == opcodes.SERVER_ERROR:
        print("[X] ERROR: Message server responded with an error, terminating")
        end_connection(sock)
        exit(1)
        # Server responds with an error
    elif opcode == opcodes.KEY_ACK:
        print("[*] The connection with the message server has been established")
        print(
            "[*] The ticket will last for 5 minutes, so when the time is up, you should restart the client / re-establish the connection to generate a new ticket")
        # The ticket and symmetrical key have been delivered successfully so the connection is now established
    else:
        print("[X] ERROR: Received an incompatible opcode, terminating")
        end_connection(sock)
        exit(1)
        # Received some other opcode
    return shared_key, sock


def user_menu(shared_key: bytes, client: str, sock: socket.socket) -> (bytes, socket.socket):
    """
    user_menu(): An interactive menu for the user, forwarding it into the other client actions

    :param shared_key: the shared symmetrical key
    :param client: the client uuid
    :param sock: the connected socket
    :return: the updated shared key and connection
    """
    user_input = input(
        "[#] Insert 1 to send a message, 2 to re-establish connection with the message server, or 3 to exit the program: ")
    if user_input == "1":
        send_message(shared_key, client, sock)
        return shared_key, sock
    elif user_input == "2":
        end_connection(sock)
        return establish_connection(client)
    elif user_input == "3":
        print("[*] Bye Bye!")
        exit(1)
    else:
        print("[!] WARNING: Invalid input, please try again")
        return shared_key, sock
