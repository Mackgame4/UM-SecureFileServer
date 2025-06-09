import os
import sys
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants
SALT_SIZE = 16
NONCE_SIZE = 16
KEY_SIZE = 32  # AES-256 requires 32 bytes key
MAC_KEY_SIZE = 32  # HMAC-SHA256 also uses a 32-byte key
ITERATIONS = 480000


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Derives two separate keys from the given password using PBKDF2:
    - AES key (32 bytes)
    - HMAC key (32 bytes)
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE + MAC_KEY_SIZE,  # Request 64 bytes (32 for AES, 32 for HMAC)
        salt=salt,
        iterations=ITERATIONS,
    )
    key_material = kdf.derive(password.encode())
    return key_material[:KEY_SIZE], key_material[KEY_SIZE:]


def encrypt(content: bytes, password: str) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypts data using AES-CTR mode and adds an HMAC (Encrypt-then-MAC strategy).
    Returns: (salt, nonce, HMAC signature, ciphertext)
    """
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    aes_key, mac_key = derive_keys(password, salt)

    # AES Encryption (CTR Mode)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(content) + encryptor.finalize()

    # Compute HMAC
    hmac_obj = hmac.HMAC(mac_key, hashes.SHA256())
    hmac_obj.update(cipher_text)
    signature = hmac_obj.finalize()

    return salt, nonce, signature, cipher_text


def decrypt(salt: bytes, nonce: bytes, signature: bytes, cipher_text: bytes, password: str) -> bytes:
    """
    Decrypts the ciphertext and verifies its integrity using HMAC.
    """
    aes_key, mac_key = derive_keys(password, salt)

    # Verify HMAC
    hmac_obj = hmac.HMAC(mac_key, hashes.SHA256())
    hmac_obj.update(cipher_text)
    hmac_obj.verify(signature)  # Raises exception if the signature is invalid

    # AES Decryption (CTR Mode)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce))
    decryptor = cipher.decryptor()
    return decryptor.update(cipher_text) + decryptor.finalize()


def main(args: list[str]):
    """ Command-line interface for encryption and decryption. """
    if len(args) < 2:
        error()

    command, file_name = args[0], args[1]
    password = input("Enter password: ")

    if command == "enc":
        try:
            with open(file_name, "rb") as file:
                content = file.read()
            salt, nonce, signature, cipher_text = encrypt(content, password)
            with open(file_name + ".enc", "wb") as enc_file:
                enc_file.write(salt + nonce + signature + cipher_text)
            print(f"File encrypted successfully: {file_name}.enc")
        except Exception as e:
            print(f"Encryption error: {e}")

    elif command == "dec":
        try:
            with open(file_name, "rb") as file:
                salt = file.read(SALT_SIZE)
                nonce = file.read(NONCE_SIZE)
                signature = file.read(32)  # HMAC-SHA256 output is always 32 bytes
                cipher_text = file.read()

            decrypted_data = decrypt(salt, nonce, signature, cipher_text, password)

            with open(file_name + ".dec", "wb") as dec_file:
                dec_file.write(decrypted_data)
            print(f"File decrypted successfully: {file_name}.dec")
        except Exception as e:
            print(f"Decryption error: {e}")

    else:
        error()


def error():
    """ Prints usage instructions and exits the program. """
    print("Usage:"
          "\n\tpython3 script.py enc <filename>"
          "\n\tpython3 script.py dec <filename>")
    sys.exit(1)


if __name__ == '__main__':
    main(sys.argv[1:])
