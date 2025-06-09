from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def cipher(clean_data: bytes, key: bytes) -> bytes:
    """
    Cifra texto usando AES GCM.
    """

    if not isinstance(clean_data, bytes):
        raise ValueError("clean_data must be bytes")

    # generate nonce
    nonce = os.urandom(12)

    # cipher data
    aesgcm = AESGCM(key)
    ciphered_data = aesgcm.encrypt(nonce, clean_data, b'')

    return nonce + ciphered_data


def decipher(data: bytes, key: bytes) -> bytes:
    """
    Decifra um ficheiro usando AES GCM.
    """

    if not isinstance(data, bytes):
        raise ValueError("data must be bytes")

    # Separar nonce do criptograma
    nonce = data[:12]
    ciphered_data = data[12:]

    # decipher
    aesgcm = AESGCM(key)
    clean_data = aesgcm.decrypt(nonce, ciphered_data, b'')

    return clean_data
