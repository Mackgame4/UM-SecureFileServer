import sys

def preproc(text):
    return "".join([c.upper() for c in text if c.isalpha()])

def cesar_cipher(text, shift, operation):
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A')
            if operation == 'enc':
                new_char = chr((ord(char) - base + shift) % 26 + base)
            elif operation == 'dec':
                new_char = chr((ord(char) - base - shift) % 26 + base)
            result.append(new_char)
        else:
            result.append(char)
    return "".join(result)

if len(sys.argv) != 4:
    print("Usage: python3 cesar.py <enc/dec> <chave> <mensagem>")
    sys.exit(1)

operation = sys.argv[1]
key = sys.argv[2]
message = sys.argv[3]

if operation not in ['enc', 'dec']:
    print("Invalid operation. Use 'enc' ou 'dec'.")
    sys.exit(1)

if not key.isalpha() or len(key) != 1:
    print("Invalid key. Use a single letter. (A-Z)")
    sys.exit(1)

shift = ord(key.upper()) - ord('A')

processed_text = preproc(message)
output = cesar_cipher(processed_text, shift, operation)
print(output)
