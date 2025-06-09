from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import sys

def encrypt_file(file, password, output_file):
    """Encrypts a file using ChaCha20 and stores the nonce with the ciphertext."""


    with open(file, 'rb') as f:
        plaintext = f.read()
    
    salt = os.urandom(16)
    nonce = os.urandom(16)
    

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = kdf.derive(password.encode('utf-8'))
    

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(output_file, 'wb') as f:
        f.write(salt + nonce + ciphertext)

    print(f"File encrypted successfully: {output_file}")

def decrypt_file(file, password, output_file):
    """Decrypts a file using ChaCha20 and stores the recovered plaintext in a new file."""


    with open(file, 'rb') as f:
        data = f.read()
    salt = data[:16]
    nonce = data[16:32]
    ciphertext = data[32:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = kdf.derive(password.encode('utf-8'))

    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()


    with open(output_file, 'wb') as f:
        f.write(plaintext)
    

    print(f"File decrypted successfully: {output_file}")

def main(argv):
    """Handles command-line arguments and executes the appropriate operation."""

    if len(argv) != 3:
        print("Error: Invalid arguments")
        print("Usage:")
        print("  enc <input_file> ")
        print("  dec <input_file> ")
        return

    operation = argv[1]
    if operation == "enc":
        input_file = argv[2]
        password = input("Enter password: ")
        output_file = input_file + ".enc"
        encrypt_file(input_file, password, output_file)


    elif operation == "dec":
        input_file = argv[2]
        password = input("Enter password: ")
        output_file = input_file.split(".")[0] + ".txt.dec"
        decrypt_file(input_file, password, output_file) 

    else:
        print("Error: Invalid operation")
        print("Valid operations:enc, dec")

if __name__ == "__main__":
    main(sys.argv)


