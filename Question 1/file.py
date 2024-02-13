"""
file.py

A collection of functions regarding working with files, mostly for the authentication server.
"""
from typing import Union
from uuid import uuid4
from datetime import datetime
import constants
from crypto import get_password_SHA256_digest


def get_user_key(client_id: str) -> Union[bytes, None]:
    """
    get_user_key(): find the user key stored in the clients file.

    :param client_id: the client uuid
    :return: the matching key
    """
    with open(r"clients", 'r') as f:
        lines = f.readlines()
        for line in lines:
            tup = line.split(":")
            if tup[0] == client_id:
                return bytes.fromhex(tup[2])
        print("Client doesn't exist, responding with an error")
        return None


def validate_username(username: str) -> bool:
    """
    validate_username(): makes sure a username is not too long and doesn't contain ':'.

    :param username: the username in question
    :return: True if it satisfies the conditions, False otherwise
    """
    return (len(username) <= constants.MAX_USERNAME_LENGTH) and (username.find(":") == -1)


def validate_password(password: str) -> bool:
    """
    validate_password(): makes sure a password is not too long.

    :param password: the password in question
    :return: True if it satisfies the condition, False otherwise
    """
    return len(password) <= constants.MAX_PASSWORD_LENGTH


def get_null_terminated_string(string: str) -> str:
    """
    get_null_terminated_string(): pulls out the string from the null terminated string.

    :param string: null-terminated string
    :return: the original string
    """
    index = string.find('\x00')
    return string[:index]


def free_username(username: str) -> bool:
    """
    free_username(): decides whether the username is already taken.

    :param username: the username in question
    :return: True if the username is free, False otherwise
    """
    try:
        f = open(r'clients', 'r')
    except FileNotFoundError:
        return True
    # If the clients file doesn't exist it must be the first client so the username must be free
    lines = f.readlines()
    for line in lines:
        tup = line.split(":")
        if tup[1] == username:
            return False
    return True


def store_to_file(uid, username, key, last_seen):
    """
    store_to_file(): stores a client entry to the clients file

    :param uid: the client uuid
    :param username: the client username
    :param key: the client key
    :param last_seen: the last time the username was seen
    """
    f = open('clients', 'a')
    f.write(f"{uid}:{username}:{key}:{last_seen}")
    f.close()


def register_client(username_bytes: bytes, password_bytes: bytes) -> Union[bytes, int]:
    """
    register_client(): try to register the client

    :param username_bytes: the client username represented in bytes
    :param password_bytes: the client password represented in bytes
    :return: the user uuid if successful, -1 otherwise
    """
    username = get_null_terminated_string(username_bytes.decode())
    password = get_null_terminated_string(password_bytes.decode())
    if not free_username(username):
        return -1
    # If the username isn't free we must reject this registration request
    uid = uuid4()
    digest = get_password_SHA256_digest(password).hexdigest()
    now = datetime.now().strftime(constants.TIME_FORMAT)
    store_to_file(uid.hex, username, digest, now)
    return uid.bytes


def update_client(client_id: str):
    """
    update_client(): updates the client's last seen attribute in the clients file

    :param client_id: the client uuid
    """
    try:
        with open(r"clients", 'r') as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                tup = line.split(":")
                if tup[0] == client_id:
                    now = datetime.now().strftime(constants.TIME_FORMAT)
                    tup[3] = now
                    updated_line = ":".join(tup)
                    lines[i] = updated_line
                    # Replace the last seen, and join the line back together
                    break
        with open(r"clients", 'w') as f:
            f.writelines(lines)
            # Write the updated data back into the file
    except FileNotFoundError:
        pass
