"""
cracker.py

A password cracker program used to try and crack the user password and the shared symmetrical key between the client and messaging server.
"""
from typing import Union
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad

request_packet = b'\xa1\x32\xf6\x0d\xf4\x6b\x42\xfe\xab\x4f\xb4\x52\x65\x9a\x48\xa3\x18\x03\x04\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0d\x1e\x4a\xad\x7a\x16\xc2\x48'
answer_packet = b'\x18\x43\x06\xd9\x00\x00\x00\xa1\x32\xf6\x0d\xf4\x6b\x42\xfe\xab\x4f\xb4\x52\x65\x9a\x48\xa3\xd0\x27\x32\x8e\x45\x0c\xfd\xa2\x00\x37\x9d\x7a\x43\xaa\xb5\xdd\x61\xc2\xc7\x98\x53\xdd\x99\xd7\x53\xe0\x96\x7f\x34\x82\xc4\xa3\xdc\xf2\x94\xf6\xe7\x52\xd0\x41\x7c\x7e\x9d\xcc\xfa\xb3\x33\xae\xcb\xb6\x1d\x54\x34\xf5\xab\x7a\x8c\x7a\x4d\x41\xac\x6c\xde\xfa\xad\xa0\x80\x30\xf5\x8e\x24\x40\xd0\x91\x8f\xfd\xe2\x30\x4e\x23\x18\xa1\x32\xf6\x0d\xf4\x6b\x42\xfe\xab\x4f\xb4\x52\x65\x9a\x48\xa3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa1\x62\xc9\x65\x00\x00\x00\x00\xa7\x0b\x68\x41\xc0\xe6\x53\x11\xd7\x4c\x9d\x0f\x0c\xd7\x8b\x4e\x2e\x71\x22\x18\x13\x88\xfa\x53\x4d\x7d\xda\xa8\x5f\x8c\x2b\xf8\x0f\x86\x01\x3e\xe1\xdd\x52\x39\xfb\x7d\x5d\x21\x19\x10\x90\xa1\x91\x7a\x3f\x24\xef\xda\x55\xe1\x24\x1e\x6d\xf9\x5b\x1d\x80\x68\xb6\x65\x04\x5a\xd8\x1f\x6f\x75\x5d\xa7\xfb\xf0\x9d\x64\x04\x93'
# Request packet -> opcode = 1027
# Answer packet -> opcode = 1603

IV_POSITION = 23
IV_LENGTH = 16
ENCRYPTED_NONCE_POSITION = 39
ENCRYPTED_NONCE_LENGTH = 16
NONCE_POSITION = 39
ENCRYPTED_KEY_POSITION = 55
ENCRYPTED_KEY_LENGTH = 48

def try_decrypting(ciphertext: bytes, key: bytes, iv: bytes) -> Union[bytes, None]:
    """
    try_decrypting(): decrypts a ciphertext using AES CBC mode, using the passed key and initialization vector.
    :param ciphertext: the ciphertext.
    :param key: the encryption key.
    :param iv: the initialization vector.
    :return: the original data or None if an error occurred
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        return None
    return data


def get_password_SHA256_digest(password: str) -> bytes:
    """
    get_password_SHA256_digest(): generates a newly created SHA-256 object and returns its digest after updating it using the passed password.

    :param password: the password in question
    :return: SHA-256 digest
    """
    h = SHA256.new()
    h.update(password.encode('utf-8'))
    return h.digest()


def get_iv(packet: bytes) -> bytes:
    """
    get_iv(): returns the iv portion in the packet.

    :param packet: the packet
    :return: the iv portion
    """
    return packet[IV_POSITION:IV_POSITION+IV_LENGTH]


def get_encrypted_nonce(packet: bytes) -> bytes:
    """
    get_encrypted_nonce(): returns the encrypted nonce portion in the packet.

    :param packet: the packet
    :return: the encrypted nonce portion
    """
    return packet[ENCRYPTED_NONCE_POSITION:ENCRYPTED_NONCE_POSITION+ENCRYPTED_NONCE_LENGTH]


def get_nonce(packet: bytes) -> bytes:
    """
    get_nonce(): returns the nonce portion in the packet.

    :param packet: the packet
    :return: the nonce portion
    """
    return packet[NONCE_POSITION:]


def get_encrypted_key(packet: bytes) -> bytes:
    """
    get_encrypted_key(): returns the encrypted key portion in the packet.

    :param packet: the packet
    :return: the encrypted key portion
    """
    return packet[ENCRYPTED_KEY_POSITION:ENCRYPTED_KEY_POSITION + ENCRYPTED_KEY_LENGTH]


def try_cracking(encrypted_nonce, encrypted_shared_key, iv, original_nonce, password: str):
    """
    try_cracking(): check the passed password on the passed data to check if it's the user password.

    :param encrypted_nonce: the encrypted nonce
    :param encrypted_shared_key: the encrypted shared key
    :param iv: the initialization vector
    :param original_nonce: the original nonce
    :param password: the password in question
    """
    password_key = get_password_SHA256_digest(password)
    cracked_nonce = try_decrypting(encrypted_nonce, password_key, iv)
    cracked_key = try_decrypting(encrypted_shared_key, password_key, iv)
    if cracked_key is not None and cracked_nonce == original_nonce:
        hex_string = ''.join('\\x{:02x}'.format(byte) for byte in cracked_key)
        print(f"[*] The user password is \"{password}\"")
        print("[*] The shared key for the user and the message server is", hex_string)
        exit(1)


if __name__ == "__main__":
    encrypted_shared_key = get_encrypted_key(answer_packet)
    encrypted_nonce = get_encrypted_nonce(answer_packet)
    iv = get_iv(answer_packet)
    original_nonce = get_nonce(request_packet)
    with open(r"dictionary", 'r') as f:
        passwords = f.readlines()
        for password in passwords:
            password = password[:-1]
            try_cracking(encrypted_nonce, encrypted_shared_key, iv, original_nonce, password)
            try_cracking(encrypted_nonce, encrypted_shared_key, iv, original_nonce, password.capitalize())
            try_cracking(encrypted_nonce, encrypted_shared_key, iv, original_nonce, password.upper())
        # For all passwords, try all their variations for an even bigger chance of cracking the password
        f.close()
    print("[*] Tough luck... couldn't crack")
