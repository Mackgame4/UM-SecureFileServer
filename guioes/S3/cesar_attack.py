import sys

def preproc(text):
    return "".join([c.upper() for c in text if c.isalpha()])



def cesar_atack(text, words):
    for shift in range(26):
        result = cesar_cipher(text, shift, 'dec')
        for word in words:
            if word in result:
                shift = chr((shift % 26) + ord('A'))
                return result, shift
    return None, None


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

if len(sys.argv) <3:
    print("Usage: python3 cesar_atack.py <message> [words]")
    sys.exit(1)

chipertext = preproc(sys.argv[1])
words = [preproc(w) for w in sys.argv[2:]]

result = cesar_atack(chipertext, words)
print(result)

