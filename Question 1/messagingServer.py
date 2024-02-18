"""
messagingServer.py

This file includes the main() function for the messaging server, initializing it and taking care of the main control flow.
"""
import selectors
import socket
import constants
import requests
from interact import parse_request_header
import opcodes
from messsagingServerUtil import receive_sym_key, receive_message, answer_invalid_opcode

sel = selectors.DefaultSelector()

tickets = {}


def accept(sock, mask):
    """
    accept(): standard accept function for the selector

    :param sock: the connected sock
    :param mask: the mask
    """
    conn, addr = sock.accept()
    print('[*] Accepted connection', conn, 'from', addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, read)


def read(conn, mask):
    """
    read(): read the incoming packets, and forward into the server actions.

    :param conn: the connected sock
    :param mask: the mask
    """
    header = conn.recv(requests.HEADER_LENGTH)
    # First we get the header,
    if header:
        client_id, version, opcode, payload_size = parse_request_header(header)
        payload = conn.recv(payload_size)
        # Then, we read the rest of the packet- the payload
        if payload:
            if opcode == opcodes.SEND_SYM_KEY:
                receive_sym_key(payload, conn, client_id, tickets)
            elif opcode == opcodes.SEND_MESSAGE:
                receive_message(payload, conn, client_id, tickets)
            else:
                answer_invalid_opcode(opcode, conn)
        else:
            print("[!] WARNING: Packet payload is missing")
            print("[*] Connection", conn, "is over")
            sel.unregister(conn)
            conn.close()
    else:
        print("[*] Connection", conn, "is over")
        sel.unregister(conn)
        conn.close()


if __name__ == "__main__":
    print("[*] messagingServer.py is running...")
    try:
        f = open('msg.info')
        print("[*] msg.info found")
        port = int(f.readline().split(":")[1][:-1])
        server_name = f.readline()
        if len(server_name) > constants.MAX_SERVER_NAME_LENGTH:
            print("[X] ERROR: Server name in msg.info exceeds 255 characters, terminating")
            exit(1)
            # Validate the length of the server name
        f.close()
    except FileNotFoundError:
        print("[X] ERROR: msg.info not found, terminating")
        exit(1)
    # Read the port from msg.info. if the file doesn't exist, terminate
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    sock.bind(('localhost', port))
    sock.listen()
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ, accept)

    while True:
        try:
            for key, mask in sel.select():
                callback = key.data
                callback(key.fileobj, mask)
        except Exception as e:
            print(f"[X] ERROR: Messaging server exception: {e}")
