import os
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def encrypt(content, password):
    """ Encrypts the content using ChaCha20-Poly1305 with a password-derived key. """
    salt = os.urandom(16)  # Generate a random salt
    nonce = os.urandom(12)  # Generate a nonce (12 bytes for ChaCha20-Poly1305)

    # Derive a 32-byte key from the password using PBKDF2
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = kdf.derive(password.encode())

    # Encrypt and authenticate the data
    cipher = ChaCha20Poly1305(key)
    ciphertext = cipher.encrypt(nonce, content, None)  # No additional authenticated data (AAD)

    return salt, nonce, ciphertext

def decrypt(salt, nonce, ciphertext, password):
    """ Decrypts the ciphertext using ChaCha20-Poly1305 with a password-derived key. """
    # Derive the key from the password
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    key = kdf.derive(password.encode())

    # Decrypt and verify the integrity of the data
    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, ciphertext, None)

def main(args):
    """ Handles encryption and decryption based on command-line arguments. """
    if len(args) < 2:
        error()

    file_name = args[1]
    password = input("Password: ")

    if args[0] == 'enc':
        with open(file_name, 'rb') as file:
            content = file.read()
        salt, nonce, ciphertext = encrypt(content, password)

        with open(file_name + '.enc', 'wb') as file:
            file.write(salt + nonce + ciphertext)

    elif args[0] == 'dec':
        with open(file_name, 'rb') as file:
            salt, nonce, ciphertext = file.read(16), file.read(12), file.read()

        with open(file_name + '.dec', 'wb') as file:
            file.write(decrypt(salt, nonce, ciphertext, password))

    else:
        error()

def error():
    """ Prints usage instructions and exits. """
    print("Usage:\n\tpython3 pbenc_chacha20_poly1305.py enc <file>\n\tpython3 pbenc_chacha20_poly1305.py dec <file>")
    sys.exit(1)

if __name__ == '__main__':
    main(sys.argv[1:])
