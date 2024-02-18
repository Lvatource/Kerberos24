"""
crypto.py

A collection of functions regarding the cryptography side of the project, and the generation of cryptographical "structures"
such as the ticket, the authenticator and the encrypted key field.
"""
import binascii
from typing import Union
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import time
from struct import pack

import constants


def generate_authenticator(version: int, client_id: bytes, server_id: bytes, shared_key: bytes) -> bytes:
    """
    generate_authenticator(): generates an authenticator structure containing the passed parameters according to the instructions.

    :param version: the version of the server
    :param client_id: the uuid of the client
    :param server_id: the uuid of the server
    :param shared_key: the shared symmetrical key
    :return: an authenticator structure (represented using bytes)
    """
    auth_iv = generate_random_iv()
    version_bytes = pack("<B", version)
    encrypted_version = encrypt_aes_cbc(version_bytes, shared_key, auth_iv)
    encrypted_client_id = encrypt_aes_cbc(client_id, shared_key, auth_iv)
    encrypted_server_id = encrypt_aes_cbc(server_id, shared_key, auth_iv)
    now = int(time.time())
    time_bytes = now.to_bytes(constants.TIME_FIELD_SIZE, byteorder="little")
    encrypted_time = encrypt_aes_cbc(time_bytes, shared_key, auth_iv)
    authenticator = pack("<16s16s32s32s16s", auth_iv, encrypted_version, encrypted_client_id, encrypted_server_id,
                         encrypted_time)
    return authenticator


def get_password_SHA256_digest(password: str) -> SHA256:
    """
    get_password_SHA256_digest(): generates a newly created SHA-256 object and returns it updating it using the passed password.

    :param password: the password in question
    :return: SHA-256 object, after being updated on the passed password
    """
    h = SHA256.new()
    h.update(password.encode('utf-8'))
    return h


def generate_encrypted_key_field(nonce: bytes, shared_key: bytes, user_key: bytes) -> bytes:
    """
    generate_encrypted_key_field(): generates an encrypted key field structure containing the passed parameters according to the instructions.

    :param nonce: the generated nonce
    :param shared_key: the shared symmetrical key
    :param user_key: the key of the user
    :return: an encrypted key field structure (represented using bytes)
    """
    user_iv = generate_random_iv()
    encrypted_nonce = encrypt_aes_cbc(nonce, user_key, user_iv)
    encrypted_shared_key = encrypt_aes_cbc(shared_key, user_key, user_iv)
    encrypted_key_field = pack("<16s16s48s", user_iv, encrypted_nonce, encrypted_shared_key)
    return encrypted_key_field


def generate_ticket(version: int, client_id: bytes, server_id: bytes, shared_key: bytes) -> Union[bytes, None]:
    """
    generate_ticket(): generates a ticket structure containing the passed parameters according to the instructions.
    :param version: the version of the server
    :param client_id: the uuid of the client
    :param server_id: the uuid of the server
    :param shared_key: the shared symmetrical key
    :return: a ticket structure (represented by bytes) or None in case of an error
    """
    try:
        f = open('msg.info')
        for i in range(0, 4):
            b64_msg_key = f.readline()
    # Try to get the message server's key from the msg.info file
    except FileNotFoundError:
        print("[X] ERROR: msg.info file doesn't exist for the authentication server, responding with an error")
        return None
    # In case the file doesn't exist, we return None in order to signal to the calling function something went wrong
    msg_key = b64_key_decrypt(b64_msg_key)
    if msg_key is None:
        print("[!] WARNING: Key in msg.info is incompatible")
        return None
    msg_iv = generate_random_iv()
    encrypted_shared_key = encrypt_aes_cbc(shared_key, msg_key, msg_iv)
    now = int(time.time())
    expired = int(time.time() + constants.EXPIRATION_TIME)
    # 5 minutes expiration time
    time_bytes = now.to_bytes(constants.TIME_FIELD_SIZE, byteorder="little")
    expired_bytes = expired.to_bytes(constants.TIME_FIELD_SIZE, byteorder="little")
    encrypted_time = encrypt_aes_cbc(expired_bytes, msg_key, msg_iv)
    ticket = pack("<1B16s16s8s16s48s16s", version, client_id, server_id, time_bytes, msg_iv, encrypted_shared_key,
                  encrypted_time)
    return ticket


def b64_key_decrypt(key_str: str) -> bytes:
    """
    b64_key_decrypt(): decode base64-encoded bytes represented as a hexadecimal string.

    :param key_str: hexadecimal string representing some base64-encoded bytes
    :return: the original bytes
    """
    key = bytes.fromhex(key_str)
    try:
        decoded_key = base64.b64decode(key)
    except binascii.Error:
        print("[!] WARNING: Something went wrong with the decryption")
        decoded_key = None
    return decoded_key


def generate_random_nonce() -> bytes:
    """
    generate_random_nonce(): generates a random 8 byte nonce.

    :return: a random 8 byte nonce
    """
    nonce = get_random_bytes(constants.NONCE_SIZE)
    return nonce


def generate_random_iv() -> bytes:
    """
    generate_random_iv(): generates a random 16 byte initialization vector.

    :return: a random 16 byte initialization vector
    """
    iv = get_random_bytes(constants.IV_FIELD_SIZE)
    return iv


def generate_random_key() -> bytes:
    """
    generate_random_key(): generates a random 32 byte key.

    :return: a random 32 byte key.
    """
    key = get_random_bytes(constants.KEY_SIZE)
    return key


def encrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    """
    encrypt_aes_cbc(): encrypt data using the AES CBC mode (padding included).

    :param data: the data to be encrypted
    :param key: the key to the encryption
    :param iv: the initialization vector
    :return: the encrypted data
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return ciphertext


def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    decrypt_aes_cbc(): decrypt ciphertext using the AES CBC mode.

    :param ciphertext: the ciphertext in question
    :param key: the key to the encryption
    :param iv: the initialization vector
    :return: the original data
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        print("[!] WARNING: Something went wrong with the decryption")
        data = None
    return data
