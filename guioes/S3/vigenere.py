import sys

def preproc(text):
    return "".join([c.upper() for c in text if c.isalpha()])

def vigenere_cipher(text, key, operation):
    result = []
    key_len = len(key)
    for i, char in enumerate(text):
        if char.isalpha():
            base = ord('A')
            shift = ord(key[i % key_len]) - base
            if operation == 'enc':
                new_char = chr((ord(char) - base + shift) % 26 + base)
            elif operation == 'dec':
                new_char = chr((ord(char) - base - shift) % 26 + base)
            result.append(new_char)
        else:
            result.append(char)
    return "".join(result)

if len(sys.argv) != 4:
    print("Usage: python3 vigenere.py <enc/dec> <key_word> <message>")
    sys.exit(1)

operation = sys.argv[1]
key = sys.argv[2]
message = sys.argv[3]

if operation not in ['enc', 'dec']:
    print("Invalid operation. Use 'enc' ou 'dec'.")
    sys.exit(1)

if not key.isalpha():
    print("Invalid key. Use only letters. (A-Z)")
    sys.exit(1)

key = preproc(key)
processed_text = preproc(message)
output = vigenere_cipher(processed_text, key, operation)
print(output)