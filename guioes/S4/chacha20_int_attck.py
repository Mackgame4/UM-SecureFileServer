import sys

def modify_ciphertext(file_name, position, plaintext_at_pos, new_plaintext_at_pos):
    """Modifies a ciphertext by flipping the necessary bits to replace a known plaintext fragment."""
    
    with open(file_name, 'rb') as f:
        ciphertext = bytearray(f.read())
        
    nonce_size = 16
    ciphertext_data = ciphertext[nonce_size:]

    if position + len(plaintext_at_pos) > len(ciphertext_data):
        print("Error: Position out of bounds.")
        return

    # Convert plaintexts to byte format
    ptxt_bytes = plaintext_at_pos.encode()
    new_ptxt_bytes = new_plaintext_at_pos.encode()

    if len(ptxt_bytes) != len(new_ptxt_bytes):
        print("Error: Plaintext fragments must have the same length.")
        return

    # Modify the ciphertext using XOR
    for i in range(len(ptxt_bytes)):
        ciphertext[nonce_size + position + i] ^= ptxt_bytes[i] ^ new_ptxt_bytes[i]

    # Save the modified ciphertext
    with open(file_name + ".attck", 'wb') as f:
        f.write(ciphertext)

    print("Ciphertext modified successfully: saved as", file_name + ".attck")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python chacha20_int_attck.py <fctxt> <pos> <ptxtAtPos> <newPtxtAtPos>")
        sys.exit(1)

    file_name = sys.argv[1]
    position = int(sys.argv[2])
    plaintext_at_pos = sys.argv[3]
    new_plaintext_at_pos = sys.argv[4]

    modify_ciphertext(file_name, position, plaintext_at_pos, new_plaintext_at_pos)
