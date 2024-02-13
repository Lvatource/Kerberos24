"""
authenticationServer.py

This file includes the main() function for the authentication server, initializing it and taking care of the main control flow.
"""
import selectors
import socket
import constants
import opcodes
from authenticationServerUtil import commence_registration, send_sym_key, answer_invalid_opcode
from file import update_client
from interact import parse_request_header, get_request_payload

sel = selectors.DefaultSelector()


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
    data = conn.recv(constants.MAX_PACKET_LENGTH)
    if data:
        client_id, version, opcode, payload_size = parse_request_header(data)
        payload = get_request_payload(data)
        update_client(client_id)
        # Update the client last seen attribute
        if opcode == opcodes.REGISTER_CLIENT:
            commence_registration(payload, conn)
        elif opcode == opcodes.REQUEST_SYM_KEY:
            send_sym_key(payload, conn, client_id)
        else:
            answer_invalid_opcode(opcode, conn)
    else:
        print("[*] Connection ", conn, " is over")
        sel.unregister(conn)
        conn.close()


if __name__ == "__main__":
    print("[*] authenticationServer.py is running...")
    try:
        f = open('port.info')
        port = int(f.read())
        print("[*] Port found")
    except FileNotFoundError:
        print("[!] WARNING: port.info not found, the authentication server's port is defaulting into 1256")
        port = constants.DEFAULT_PORT
    # If the port file doesn't exist, default into the default port
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
            print(f"[X] ERROR: Authentication server exception: {e}")
