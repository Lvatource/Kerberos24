"""
client.py

This file includes the main() function for the client, initializing it and taking care of the control flow.
"""
from clientUtil import log_in, establish_connection, user_menu

if __name__ == "__main__":
    client_id = log_in()
    shared_key, sock = establish_connection(client_id)
    while True:
        shared_key, sock = user_menu(shared_key, client_id, sock)
