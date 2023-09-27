# Import necessary functions from the utilities module
from utilities import (
    writeKeys, readKeys, generatekey, printKey,
    read_plain_text, aes_encrypt_block, pad,
    write_to_hex_file, read_from_hex_file, unpad, aes_decrypt_block, result
)
import os

# Example file paths
ciphertext_file = 'data/ciphertext.txt'
iv_file = 'data/iv.txt'

# Function to generate a random initialization vector (IV)
def generate_random_iv():
    return os.urandom(16)

# Function to perform AES encryption in CBC mode
def encrypt_aes_cbc(plaintext, key, iv):
    block_size = 16  # AES block size is 16 bytes for AES-256
    plaintext = pad(plaintext.encode('utf-8'), block_size)
    ciphertext = b''
    prev_block = iv

    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i + block_size]
        xor_block = bytes(x ^ y for x, y in zip(block, prev_block))
        encrypted_block = aes_encrypt_block(xor_block, key)
        ciphertext += encrypted_block
        prev_block = encrypted_block

    return ciphertext

# Function to perform AES decryption in CBC mode
def decrypt_aes_cbc(ciphertext, key, iv):
    block_size = 16  # AES block size is 16 bytes for AES-256
    plaintext = b''
    prev_block = iv

    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        decrypted_block = aes_decrypt_block(block, key)
        plaintext_block = bytes(x ^ y for x, y in zip(decrypted_block, prev_block))
        plaintext += plaintext_block
        prev_block = block

    return unpad(plaintext).decode('utf-8')

# Function to decrypt ciphertext
def Dec():
    sk = readKeys()
    print("SECRET KEY READ")
    printKey(sk)

    c = read_from_hex_file(ciphertext_file)
    iv = read_from_hex_file(iv_file)

    decrypted_plaintext = decrypt_aes_cbc(c, sk, iv)
    print("DECRYPTED TEXT: ", decrypted_plaintext)
    result(decrypted_plaintext)

# Function to encrypt plaintext
def Enc():
    sk = readKeys()
    print("SECRET KEY READ")
    printKey(sk)

    f = read_plain_text()
    print("PLAIN TEXT: ", f)

    iv = generate_random_iv()
    print("RANDOM IV: ", iv)

    c = encrypt_aes_cbc(f, sk, iv)
    print("CIPHERTEXT: ", c)

    # Write ciphertext to file
    write_to_hex_file(c, ciphertext_file)

    # Write IV to file
    write_to_hex_file(iv, iv_file)

# Function to generate secret key, encrypt, and decrypt
def genKeys():
    sk = generatekey()
    printKey(sk)
    writeKeys(sk)

# Main function
def main():
    genKeys()
    Enc()
    Dec()

if __name__ == "__main__":
    main()
