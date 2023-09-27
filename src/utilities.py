import secrets
from hashlib import sha256
from base64 import b64encode, b64decode


def writeKeys(key, filename='data/key.txt'):
    hex_key = key.hex()  # Convert the bytes key to hexadecimal string
    with open(filename, 'w') as file:
        file.write(hex_key)
        

def readKeys(filename='data/key.txt'):
    try:
        with open(filename, 'r') as file:
            hex_key = file.read().strip()  # Read the hexadecimal key as a string
            key = bytes.fromhex(hex_key)  # Convert the hexadecimal string to bytes
        return key
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        return None


def generatekey():
    # Generate a random 256-bit key
    key = secrets.token_bytes(32)
    return key


def printKey(sk):
    if sk:
        print(f'key:')
        hex_values = ' '.join([format(byte, '02X') for byte in sk])
        print(hex_values)


def read_plain_text(filename='data/plaintext.txt'):
    try:
        with open(filename, 'r') as file:
            text = file.read()
        return text
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        return None

def aes_encrypt_block(block, key):
    # This example uses AES-256
    key_hash = sha256(key).digest()
    # Perform your AES encryption logic here (e.g., using bitwise operations)
    # For educational purposes, this example uses a simple XOR operation
    encrypted_block = bytes(x ^ y for x, y in zip(block, key_hash))
    return encrypted_block

# Function to pad the plaintext to match the block size
def pad(plaintext, block_size):
    padding_length = block_size - (len(plaintext) % block_size)
    padding = bytes([padding_length] * padding_length)
    return plaintext + padding


# Function to write data to a file in hexadecimal format
def write_to_hex_file(data, filename):
    hex_data = b64encode(data).decode('utf-8')
    with open(filename, 'w') as file:
        file.write(hex_data)

# Function to read data from a file in hexadecimal format
def read_from_hex_file(filename):
    with open(filename, 'r') as file:
        hex_data = file.read()
    return b64decode(hex_data)

# Function to unpad the plaintext after decryption
def unpad(plaintext):
    padding_length = plaintext[-1]
    return plaintext[:-padding_length]


# Function to perform AES decryption on a single block
def aes_decrypt_block(block, key):
    # This example uses AES-256
    key_hash = sha256(key).digest()
    # Perform your AES decryption logic here (e.g., using bitwise operations)
    # For educational purposes, this example uses a simple XOR operation
    decrypted_block = bytes(x ^ y for x, y in zip(block, key_hash))
    return decrypted_block

def result(decrypted_plaintext):
    result_file= 'data/result.txt'
    with open(result_file, 'w') as file:
        file.write(decrypted_plaintext)