import sys
from collections import Counter

def preproc(text):
    return "".join([c.upper() for c in text if c.isalpha()])

def cesar_cipher(text, shift):
    result = []
    for char in text:
        base = ord('A')
        new_char = chr((ord(char) - base - shift) % 26 + base)
        result.append(new_char)
    return "".join(result)

PORTUGUESE_FREQ = ['A', 'E', 'O', 'S', 'R', 'I', 'N']
def find_shift(slice):
    freq = Counter(slice)
    print (freq)
    most_common = freq.most_common(1)[0][0]
    print (most_common)
    shifts = [(ord(most_common) - ord(c)) % 26 for c in PORTUGUESE_FREQ]
    print (shifts)
    return shifts[0] 

def vigenere_attack(cipher_text, key_len):
    slices = ['' for _ in range(key_len)]
    for i, char in enumerate(cipher_text):
        slices[i % key_len] += char

    key = []
    for slice in slices:
        shift = find_shift(slice)
        key.append(chr((shift % 26) + ord('A')))

    key = ''.join(key)
    decrypted = vigenere_cipher(cipher_text, key)
    return decrypted, key


def vigenere_cipher(text, key):
    result = []
    key_len = len(key)
    for i, char in enumerate(text):
        base = ord('A')
        shift = ord(key[i % key_len]) - base
        new_char = chr((ord(char) - base - shift) % 26 + base)
        result.append(new_char)
    return "".join(result)

if len(sys.argv) < 3:
    print("Uso: python3 vigenere_attack.py <key_len> <ciphered_message>")
    sys.exit(1)

key_len = int(sys.argv[1])
ciphertext = preproc(sys.argv[2])

result = vigenere_attack(ciphertext, key_len)
print("Chave encontrada:", result[1])
print("Texto decifrado:", result[0])

## P GR G AR H SF H PR G CV H OJ H WE P ZR S CJ F IV S OF R WU T BK P ZG G OZ P ZL H WK P BR
