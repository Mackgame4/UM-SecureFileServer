from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
import os
import sys

def generate_key(file_key):
    """Generates a 32-byte key and saves it to a file."""
    key = os.urandom(32)
    with open(file_key, 'wb') as f:
        f.write(key)
    print(f"Key generated successfully: {file_key}")

def encrypt_file(file, key_file, output_file):
    """Encrypts a file using ChaCha20 and stores the nonce with the ciphertext."""

    # Read plaintext from file
    with open(file, 'rb') as f:
        plaintext = f.read()
    
    # Generate a 16-byte nonce
    nonce = os.urandom(16)

    # Read encryption key from file
    with open(key_file, 'rb') as f:
        key = f.read()
    
    # Create cipher and encrypt the file
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save the nonce and encrypted text in the output file
    with open(output_file, 'wb') as f:
        f.write(nonce + ciphertext)

    print(f"File encrypted successfully: {output_file}")

def decrypt_file(file, key_file, output_file):
    """Decrypts a file using ChaCha20 and stores the recovered plaintext in a new file."""

    # Read encrypted file
    with open(file, 'rb') as f:
        data = f.read()

    # Extract nonce and ciphertext
    nonce = data[:16]  # First 16 bytes are the nonce
    ciphertext = data[16:]

    # Read decryption key from file
    with open(key_file, 'rb') as f:
        key = f.read()
    
    # Create cipher and decrypt the file
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Save decrypted text
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"File decrypted successfully: {output_file}")

def main(argv):
    """Handles command-line arguments and executes the appropriate operation."""

    if len(argv) < 3:
        print("Error: Invalid arguments")
        print("Usage:")
        print("  setup <keyfile>")
        print("  enc <input_file> <keyfile>")
        print("  dec <input_file> <keyfile>")
        return

    operation = argv[1]

    if operation == "setup":
        file_key = argv[2]
        generate_key(file_key)

    elif operation == "enc":
        if len(argv) < 4:
            print("Error: Missing input file or key file")
            return
        input_file = argv[2]
        key_file = argv[3]
        output_file = input_file + ".enc"
        encrypt_file(input_file, key_file, output_file)

    elif operation == "dec":
        if len(argv) < 4:
            print("Error: Missing input file or key file")
            return
        input_file = argv[2]
        key_file = argv[3]
        output_file = input_file + ".dec"
        decrypt_file(input_file, key_file, output_file)

    else:
        print("Error: Invalid operation")
        print("Valid operations: setup, enc, dec")

if __name__ == "__main__":
    main(sys.argv)


# 
### QUESTÃO: Q2

### Qual o impacto de se considerar um *NONCE* fixo (e.g. tudo `0`)? Que implicações terá essa prática na segurança da cifra?

### RESPOSTA:
###
### O uso de um nonce fixo em criptografias como ChaCha20 compromete seriamente a segurança da comunicação, podendo resultar na recuperação de textos cifrados e até na dedução da chave de cifra. Por isso, é fundamental que cada mensagem cifrada tenha um nonce único e aleatório para garantir a segurança da comunicação.
###
###