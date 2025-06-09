from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

import os
import sys

def gerar_chave(fkey):
    """
    Generating a key and saving it into a new file.
    """
    chave = os.urandom(32)
    with open(fkey, "wb") as f:
        f.write(chave)

def cifrar_ficheiro(fich, fkey, fsaida):
    """
    Encrypts a file using AES CTR.
    """
    with open(fich, "rb") as f:
        texto_limpo = f.read()

    with open(fkey, "rb") as f:
        chave = f.read()

    nonce = os.urandom(16)

    cifra = Cipher(algorithms.AES(chave), mode=modes.CTR(nonce))
    encryptor = cifra.encryptor()
    texto_encriptado = encryptor.update(texto_limpo) + encryptor.finalize()

    with open(fsaida, "wb") as f:
        f.write(nonce + texto_encriptado)

def decifrar_ficheiro(fich, fkey, fsaida):
    """
    Decrypts a file using AES CTR.
    """
    with open(fich, "rb") as f:
        data = f.read()

    nonce = data[:16]
    texto_encriptado = data[16:]
    with open(fkey, "rb") as f:
        chave = f.read()

    cifra = Cipher(algorithms.AES(chave), mode=modes.CTR(nonce))
    decryptor = cifra.decryptor()
    texto_limpo = decryptor.update(texto_encriptado) + decryptor.finalize()

    with open(fsaida, "wb") as f:
        f.write(texto_limpo)


def main(argv: list[str]):

    operacao = argv[1]

    if operacao == "setup":
        if not argv[2]:
            print("Error: key file not specified")
            return
        fkey = argv[2]
        gerar_chave(fkey)
        print("Key generated at:", fkey)

    elif operacao == "enc":
        if not argv[2] or not argv[3]:
            print("Error: file or key not specified")
            return
        fich, fkey = argv[2], argv[3]
        fsaida = fich + ".enc"
        cifrar_ficheiro(fich, fkey, fsaida)
        print("File encrypted at:", fsaida)

    elif operacao == "dec":
        if not argv[2] or not argv[3]:
            print("Error: file or key not specified")
            return
        fich, fkey = argv[2], argv[3]
        fsaida = fich.split(".")[0] + ".txt.dec"
        decifrar_ficheiro(fich, fkey, fsaida)
        print("File decrypted at:", fsaida)

    else:
        print("Erro: Invalid operation")


if __name__ == "__main__":
    main(sys.argv)