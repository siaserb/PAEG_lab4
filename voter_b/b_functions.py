import os
import socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils


def send_data(data, port):
    s = socket.socket()
    s.connect(('127.0.0.1', port))
    if isinstance(data, str):
        s.send(data.encode())
    else:
        s.send(data)
    s.close()


def receive_data(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(1)

    c, addr = s.accept()
    received_data = b''
    while True:
        chunk = c.recv(262144)
        if not chunk:
            break
        received_data += chunk

    c.close()
    s.close()
    return received_data


def generate_random_string(length=4):
    random_bytes = os.urandom(length)
    random_hex_string = random_bytes.hex()
    return random_hex_string


def add_random_string(message, random_string):
    if message is None:
        raise ValueError("Input message is None")
    if isinstance(message, int):
        message = str(message)
        return message.encode('utf-8') + random_string.encode('utf-8')
    elif isinstance(message, bytes):
        return message + random_string.encode('utf-8')
    elif isinstance(message, str):
        return message.encode('utf-8') + random_string.encode('utf-8')
    else:
        raise ValueError("Unsupported message type")


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt(message, public_key):
    max_block_size = 100

    blocks = [message[i:i + max_block_size] for i in range(0, len(message), max_block_size)]

    encrypted_blocks = []
    for block in blocks:
        ciphertext = public_key.encrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_blocks.append(ciphertext)

    return b''.join(encrypted_blocks)


def decrypt(ciphertext, private_key):
    max_block_size = 256

    encrypted_blocks = [ciphertext[i:i + max_block_size] for i in range(0, len(ciphertext), max_block_size)]

    decrypted_blocks = []
    for block in encrypted_blocks:
        plaintext = private_key.decrypt(
            block,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_blocks.append(plaintext)

    return b''.join(decrypted_blocks)


def remove_string(byte_string, num_bytes):
    return byte_string[:-num_bytes]


def choose_candidate(candidates):
    while True:
        candidate = int(input('Введіть номер кандидата:'))
        if candidate in candidates:
            break
        else:
            print('Кандидат невірний!')
            continue

    return candidate


def serialize_public_key(public_key):
    serialized_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serialized_key


def deserialize_public_key(serialized_key):
    public_key = serialization.load_pem_public_key(
        serialized_key,
        backend=default_backend()
    )
    return public_key


def check_string(string, strings):
    if string.encode('utf-8') in strings:
        print('String check was successful!')
    else:
        raise Exception('Wrong string!')


def check_encrypted_message(m1, m2):
    try:
        for i in range(4):
            for j in range(4):
                if m1[i] == m2[j]:
                    print('Encrypted message check was successful!')
    except Exception:
        raise Exception('Encrypted message check failed!')


def generate_keys_elgamal():
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(private_key, message):
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def hash_message(message):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(message)
    return digest.finalize()


def verify_signature(public_key, signature, hashed_message):
    try:
        public_key.verify(signature, hashed_message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        print('Verification was successful!')
    except Exception:
        raise Exception('Verification failed!')


def serialize_public_key_elgamal(public_key):
    pem = public_key.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def deserialize_public_key_elgamal(pem):
    public_key = serialization.load_pem_public_key(pem, backend=default_backend())
    return public_key


def extract_last_8_bytes(data):
    return data[-8:]


def check_amount_of_messages(voters, votes):
    if len(voters) == len(votes):
        print('Amount of votes is correct!')
    else:
        raise Exception('Amount of votes is not correct!')


def reorder_list(lst, idx):
    return [lst[i] for i in idx]
