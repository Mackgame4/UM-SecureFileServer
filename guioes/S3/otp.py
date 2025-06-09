import os
import sys

def otp(op, bytes, file):
    if op == "setup":
        with open(file, "wb") as f:
            f.write(os.urandom(int(bytes)))
    elif op == "enc":
        msg = ""
        with open(file, "rb") as key:
            with open(bytes, "r") as msg_file:
                text = msg_file.read()
                for i in range(0, len(text)):
                    msg += chr(ord(text[i]) ^ ord(key.read(1)))
        with open(bytes + ".enc", "w") as f:
            f.write(msg)
    elif op == "dec":
        msg = ""
        with open(file, "rb") as key:
            with open(bytes, "r") as msg_file:
                text = msg_file.read()
                for i in range(0, len(text)):
                    msg += chr(ord(text[i]) ^ ord(key.read(1)))  
        with open(bytes + ".dec", "w") as f:
            f.write(msg)

def main():
    if len(sys.argv) != 4:
        print("Usage: python otp.py <enc|dec> <key> <message>")
    op = sys.argv[1]
    bytes = sys.argv[2]
    file = sys.argv[3]
    otp(op, bytes, file)

if __name__ == "__main__":
    main()