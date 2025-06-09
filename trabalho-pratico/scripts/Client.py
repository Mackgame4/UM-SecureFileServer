import asyncio
import argparse
import os
import utils.aes_gcm as aes_gcm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509.oid import NameOID
from utils.msg_serialization import mkpair, unpair, MessageSerializer, Permission
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from utils.validate_cert import valida_cert
import bson
from utils.command_handler import (handle_exit, handle_add, handle_list, handle_read, handle_share, handle_delete, handle_replace, 
                             handle_details, handle_revoke, handle_group_create, handle_group_delete, handle_group_add_user, 
                             handle_group_delete_user, handle_group_list, handle_group_add_file)
from tabulate import tabulate


conn_port = 8443
max_msg_size = 9999
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2

def encrypt_data(data, key):
    encrypted_data = aes_gcm.cipher(data, key)
    return encrypted_data

def chiper_file_content(content):
    aes_key = AESGCM.generate_key(bit_length=256)  # Chave AES de 256 b
    return aes_key

class Client:
    def __init__(self, p12_name):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(base_dir, "../projCA", p12_name)
        with open(full_path, "rb") as p12_file:
            self.private_key, self.cert, _ = pkcs12.load_key_and_certificates(
                p12_file.read(), password=None
            )

        self.pseudonym = self.cert.subject.get_attributes_for_oid(NameOID.PSEUDONYM)[0].value
        print(f"Client pseudonym: {self.pseudonym}")
        
        # Generate DH parameters and key pair
        self.dh_private_key = dh.DHParameterNumbers(
            p, g).parameters().generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
        
        self.shared_key = None
        self.reader = None
        self.writer = None

    async def secure_terminate(self, message):
        """Close connection securely with error message"""
        self.writer.write(message.encode())
        await self.writer.drain()
        self.writer.close()
        await self.writer.wait_closed()

    async def send_command(self, command_data: bytes):
        """Envia comando para o servidor e retorna a resposta"""
        try:
            self.writer.write(command_data)
            await self.writer.drain()
            # Recebe a resposta
            response_data = await self.reader.read(max_msg_size)
            return MessageSerializer.deserialize(response_data)
        except Exception as e:
            print(f"Error sending command: {e}")
            return None

    async def authenticate(self):
        try:
            # Step 1: Send client pseudonym
            self.writer.write(self.pseudonym.encode())
            await self.writer.drain()

            # Step 2: Receive server nonce, signature and certificate
            server_data = await self.reader.read(max_msg_size)
            nonce, server_sig_cert = unpair(server_data)
            server_sig, server_cert_pem = unpair(server_sig_cert)
            server_cert = x509.load_pem_x509_certificate(server_cert_pem)

            if not valida_cert(server_cert, "SSI Vault Server"):
                raise Exception("Invalid server certificate")

            # Verify server signature
            try:
                server_cert.public_key().verify(
                    server_sig,
                    nonce,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except InvalidSignature:
                print("🛑 ALERT: Invalid signature - possible attack attempt!")
                await self.secure_terminate("Authentication failed: invalid signature")
                return False
            except Exception as e:
                print(f"🛑 Unexpected verification error: {str(e)}")
                await self.secure_terminate("Internal authentication error")
                return False

            # Step 3: Sign nonce and send response with client certificate
            client_sig = self.private_key.sign(
                nonce,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            response = mkpair(
                client_sig,
                self.cert.public_bytes(serialization.Encoding.PEM)
            )
            self.writer.write(response)
            await self.writer.drain()

            # Step 4: Receive authentication result and server DH public key 'signature 
            # auth_success_msg = mkpair(
            #     mkpair(
            #         dh_public_bytes,
            #         dh_public_key_signature
            #     ),
            #     b"AUTH_SUCCESS"
            # )
            auth_result = await self.reader.read(max_msg_size)
            # server sends a pair with a pair containing the server's DH public key and the authentication status
            server_dh_public_bytes_pair, auth_status = unpair(auth_result)

            if auth_status != b"AUTH_SUCCESS":
                raise Exception("Server rejected authentication")
            
            # Load server's DH public key
            server_dh_public_bytes, signature = unpair(server_dh_public_bytes_pair)

            #verify server's DH public key signature
            try:
                server_cert.public_key().verify(
                    signature,
                    server_dh_public_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except InvalidSignature:
                print("🛑 ALERT: Invalid signature - possible attack attempt!")
                await self.secure_terminate("Authentication failed: invalid signature")
                return False
            except Exception as e:
                print(f"🛑 Unexpected verification error: {str(e)}")
                await self.secure_terminate("Internal authentication error")
                return False

            server_dh_public_key = serialization.load_pem_public_key(
                server_dh_public_bytes
            )
            # print("Mutual authentication successful!")

            # Step 5: Send client's DH public key to server
            client_dh_public_bytes = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            # Sign the client's DH public key
            client_dh_public_key_signature = self.private_key.sign(
                client_dh_public_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            # Send the signed client's DH public key
            client_dh_public_key_pair = mkpair(
                client_dh_public_bytes,
                client_dh_public_key_signature
            )
            self.writer.write(client_dh_public_key_pair)
            await self.writer.drain()

            # Step 6: Derive shared key
            shared_key = self.dh_private_key.exchange(server_dh_public_key)
            
            # Perform key derivation
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)

           # print(f"Shared key derived successfully: {self.shared_key.hex()}")
            return True

        except Exception as e:
            print(f"Authentication failed: {e}")
            return False

    async def command_loop(self):
     while True:
        try:

            command = input("> ").strip()
            if not command:
                continue

            parts = command.split()
            cmd = parts[0].lower()

            if cmd == "exit":
                if handle_exit():
                    break

            elif cmd == "add" and len(parts) >= 2:
                file_path = parts[1].strip("'")
                if os.path.exists(file_path):
                    with open(file_path, "rb") as f:
                        content = f.read()
                    key = chiper_file_content(content)
                    encrypted_content = aes_gcm.cipher(content, key)
                    public_key_obj = self.cert.public_key()
                    encrypted_key = public_key_obj.encrypt(
                        key,
                        padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    data = handle_add(encrypted_content, encrypted_key)
                    encrypted_data = encrypt_data(data, self.shared_key)
                    self.writer.write(encrypted_data)
                    # receiving the response
                    response = await self.reader.read(max_msg_size)
                    # decrypting the response
                    decrypted_response = aes_gcm.decipher(response, self.shared_key)
                    response = bson.loads(decrypted_response)
                    print(response["file_id"])
                else:
                    print(f"File {file_path} does not exist. Please provide a valid file path.")

            elif cmd == "list":
                user_id = None
                group_id = None
                if len(parts) >= 3:
                    if parts[1] == "-u":
                        user_id = parts[2]
                    elif parts[1] == "-g":
                        group_id = parts[2]
                data = handle_list(user_id, group_id)
                encrypted_data = encrypt_data(data, self.shared_key)  
                self.writer.write(encrypted_data)
                await self.writer.drain()
                response = await self.reader.read(max_msg_size)
                decrypted_response = aes_gcm.decipher(response, self.shared_key)
                response = bson.loads(decrypted_response)
                if response["status"] == "ok":
                    print(response["file_id"]["message"])
                else:
                    print( response["message"])


            elif cmd == "read" and len(parts) >= 2:
                file_id = parts[1]
                data = handle_read(file_id)
                encrypted_data = encrypt_data(data, self.shared_key)  
                self.writer.write(encrypted_data)
                response = await self.reader.read(max_msg_size)

                decrypted_response = aes_gcm.decipher(response, self.shared_key)
                response = bson.loads(decrypted_response)
                if response["status"] == "ok":
                    # Decrypt the file content
                    encrypted_content = response["content"]
                    encrypted_key = response["encrypted_key"]
                    decrypted_key = self.private_key.decrypt(
                        encrypted_key,
                        padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    decrypted_content = aes_gcm.decipher(encrypted_content, decrypted_key)
                    data = [[decrypted_content.decode("utf-8")]]
                    print(tabulate(data, tablefmt="grid"))
                else:
                    print("Error reading file:", response["message"])

            elif cmd == "share" and len(parts) >= 4:
                file_id = parts[1]
                user_id = parts[2]
                permissions = [Permission(p) for p in parts[3:]]
                
                
                data = handle_share(file_id, user_id, permissions)
                encrypted_data = encrypt_data(data, self.shared_key)
                self.writer.write(encrypted_data)
                await self.writer.drain()

                
                response = await self.reader.read(max_msg_size)
                decrypted_response = aes_gcm.decipher(response, self.shared_key)
                response_data = bson.loads(decrypted_response)

                if response_data["status"] == "ok":
                    if "user_id" in response_data and "encrypted" in response_data and "user_public_key" in response_data:
                        user_id = response_data["user_id"]
                        encrypted_key = response_data["encrypted"]
                        user_public_key = response_data["user_public_key"]
                        user_public_key = serialization.load_pem_public_key(user_public_key)
                        
                        decrypted_key = self.private_key.decrypt(
                            encrypted_key,
                            padding.OAEP(
                                mgf=padding.MGF1(hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        
                        new_encrypted_key = user_public_key.encrypt(
                            decrypted_key,
                            padding.OAEP(
                                mgf=padding.MGF1(hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        
                        encrypted_message = encrypt_data(new_encrypted_key, self.shared_key)
                        self.writer.write(encrypted_message)
                        await self.writer.drain()
                        
                        final_response = await self.reader.read(max_msg_size)
                        decrypted_final = aes_gcm.decipher(final_response, self.shared_key)
                        final_data = bson.loads(decrypted_final)
                        if final_data["status"] == "ok":
                            print(final_data["message"])
                    else:
                        print(response_data["message"])
                else:
                    print(f"Error: {response_data['message']}")
            elif cmd == "delete" and len(parts) >= 2:
                file_id = parts[1]
                data = handle_delete(file_id)
                encrypted_data = encrypt_data(data, self.shared_key)  # Usar a função
                self.writer.write(encrypted_data)
                await self.writer.drain()
                # Ler resposta do servidor
                response = await self.reader.read(max_msg_size)
                decrypted_response = aes_gcm.decipher(response, self.shared_key)
                response = bson.loads(decrypted_response)
                if response["status"] == "ok":
                    print(response["file_id"]["message"])
                else:
                    print("Error deleting file:", response["message"])
            elif cmd == "replace" and len(parts) >= 3:
                file_id = parts[1]
                file_path = parts[2].strip("'") # filter the first and last ' if they exist
                if os.path.exists(file_path):
                    # Lê o conteúdo do ficheiro
                    with open(file_path, "rb") as f:
                        content = f.read()
                    
                    # Encripta o conteúdo do ficheiro
                    key = chiper_file_content(content)
                    encrypted_content = aes_gcm.cipher(content, key)
                    
                    # Encripta a chave do ficheiro com a chave pública do servidor
                    public_key_obj = self.cert.public_key()
                    encrypted_key = public_key_obj.encrypt(
                        key,
                        padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Envia o pedido de replace com o ficheiro e a chave encriptada
                    data = handle_replace(file_id, encrypted_content, encrypted_key)
                    encrypted_data = encrypt_data(data, self.shared_key)  # Encripta os dados com a chave compartilhada
                    self.writer.write(encrypted_data)
                    await self.writer.drain()
                    
                    # Espera pela resposta do servidor
                    encrypted_response = await self.reader.read(max_msg_size)
                    decrypted_response = aes_gcm.decipher(encrypted_response, self.shared_key)
                    response = bson.loads(decrypted_response)
                    
                    # Verifica se o status da resposta é 'replace'
                    if response.get("status") == "replace":
                        # Recebe as chaves públicas dos leitores
                        readers_public_keys = response["readers_public_keys"]
                        
                        encrypted_keys = {}
                        
                        # Reencripta a chave para cada leitor
                        for user_id, pubkey_pem in readers_public_keys.items():
                            pubkey = serialization.load_pem_public_key(pubkey_pem)
                            
                            # Encripta a chave do ficheiro com a chave pública do leitor
                            encrypted_key_for_reader = pubkey.encrypt(
                                key,
                                padding.OAEP(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            
                            # Armazena a chave encriptada para este leitor
                            encrypted_keys[user_id] = encrypted_key_for_reader

                        # Serializa e envia os dados para o servidor
                        serialized_response = MessageSerializer.response_replace_key_distribution(file_id, encrypted_keys)
                        encrypted_final = encrypt_data(serialized_response, self.shared_key)
                        self.writer.write(encrypted_final)
                        await self.writer.drain()

                        response = await self.reader.read(max_msg_size)
                        decrypted_response = aes_gcm.decipher(response, self.shared_key)
                        final_response = bson.loads(decrypted_response)
                        if final_response["status"] == "ok":
                            print(final_response["file_id"])
                    else:
                            print("Error replacing file:", response["message"])
            elif cmd == "details" and len(parts) >= 2:
                file_id = parts[1]
                data = handle_details(file_id)
                encrypted_data = encrypt_data(data, self.shared_key) 
                self.writer.write(encrypted_data)
                await self.writer.drain()
                response = await self.reader.read(max_msg_size)
                decrypted_response = aes_gcm.decipher(response, self.shared_key)
                response = bson.loads(decrypted_response)
                if response["status"] == "ok":
                    print(response["file_id"]["message"])
                else:
                    print(response["message"])
            elif cmd == "revoke" and len(parts) >= 3:
                file_id = parts[1]
                user_id = parts[2]
                data = handle_revoke(file_id, user_id)
                encrypted_data = encrypt_data(data, self.shared_key)  
                self.writer.write(encrypted_data)
                await self.writer.drain()
                # Ler resposta do servidor
                response = await self.reader.read(max_msg_size)
                decrypted_response = aes_gcm.decipher(response, self.shared_key)
                response = bson.loads(decrypted_response)
                if response["status"] == "ok":
                    print(response["file_id"]["message"])
                else:
                    print(response["message"])

            elif cmd == "group":
                if len(parts) >= 2:
                    group_cmd = parts[1].lower()

                    if group_cmd == "create" and len(parts) >= 3:
                        group_name = parts[2]
                        data = handle_group_create(group_name)
                        encrypted_data = encrypt_data(data, self.shared_key)  
                        self.writer.write(encrypted_data)
                        # receiving the response
                        response = await self.reader.read(max_msg_size)
                        # decrypting the response
                        decrypted_response = aes_gcm.decipher(response, self.shared_key)
                        response = bson.loads(decrypted_response)
                        if response["status"] == "ok":
                            print(response['group_id'])
                        else:
                            print("Error creating group:", response["message"])

                    elif group_cmd == "delete" and len(parts) >= 3:
                        group_id = parts[2]
                        data = handle_group_delete(group_id)
                        encrypted_data = encrypt_data(data, self.shared_key)
                        self.writer.write(encrypted_data)
                        await self.writer.drain()
                        # Ler resposta do servidor
                        response = await self.reader.read(max_msg_size)
                        decrypted_response = aes_gcm.decipher(response, self.shared_key)
                        response = bson.loads(decrypted_response)
                        if response["status"] == "ok":
                            print(response["file_id"]["message"])
                        else:
                            print(response["message"])

                    elif group_cmd == "add-user" and len(parts) >= 5:
                        group_id = parts[2]
                        user_id = parts[3]
                        permissions = [Permission(p) for p in parts[4:]]
                        data = handle_group_add_user(group_id, user_id, permissions)
                        encrypted_data = encrypt_data(data, self.shared_key)
                        self.writer.write(encrypted_data)
                        await self.writer.drain()

                        # Ler resposta do servidor
                        response_data = await self.reader.read(max_msg_size)
                        decrypted_response = aes_gcm.decipher(response_data, self.shared_key)
                        response = bson.loads(decrypted_response)

                        if response["status"] == "request":
                            
                            encrypted_keys = {}
                            pubkey_new_user = serialization.load_pem_public_key(
                                response["target_pubkey"]
                            )

                            for file_id, encrypted_key in response["readers_keys"].items():
                                decrypted_key = self.private_key.decrypt(
                                    encrypted_key,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                )

                                new_encrypted_key = pubkey_new_user.encrypt(
                                    decrypted_key,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                )
                                encrypted_keys[file_id] = new_encrypted_key

                            # Enviar de volta ao servidor
                            send_back = bson.dumps({
                                "encrypted_keys": {
                                    file_id: enc_key
                                    for file_id, enc_key in encrypted_keys.items()
                                }
                            })
                            self.writer.write(encrypt_data(send_back, self.shared_key))
                            await self.writer.drain()

                            # Esperar resposta final
                            final_resp = await self.reader.read(max_msg_size)
                            final_resp_dec = aes_gcm.decipher(final_resp, self.shared_key)
                            final = bson.loads(final_resp_dec)
                            print(final["file_id"])

                        elif response["status"] == "ok":
                            print(response["file_id"])

                        else:
                            print("Erro:", response["message"])

                    elif group_cmd == "delete-user" and len(parts) >= 4:
                        group_id = parts[2]
                        user_id = parts[3]
                        data = handle_group_delete_user(group_id, user_id)
                        encrypted_data = encrypt_data(data, self.shared_key)
                        self.writer.write(encrypted_data)
                        await self.writer.drain()
                        # Ler resposta do servidor
                        response = await self.reader.read(max_msg_size)
                        decrypted_response = aes_gcm.decipher(response, self.shared_key)
                        response = bson.loads(decrypted_response)
                        if response["status"] == "ok":
                            print(response["file_id"]["message"])
                        else:
                            print(response["message"])

                    elif group_cmd == "list":

                        data = handle_group_list()
                        encrypted_data = encrypt_data(data, self.shared_key)
                        self.writer.write(encrypted_data)
                        await self.writer.drain()
                        # Ler resposta do servidor
                        response = await self.reader.read(max_msg_size)
                        decrypted_response = aes_gcm.decipher(response, self.shared_key)
                        response = bson.loads(decrypted_response)
                        if response["status"] == "ok":
                            print(response["file_id"]["message"])
                        else:
                            print(response["message"])

                    elif group_cmd == "add" and len(parts) >= 4:
                        group_id = parts[2]
                        file_path = parts[3].strip("'")
                        if os.path.exists(file_path):
                            with open(file_path, "rb") as f:
                                    content = f.read()
                            key = chiper_file_content(content)
                            encrypted_content = aes_gcm.cipher(content, key)
                            public_key_obj = self.cert.public_key()
                            encrypted_key = public_key_obj.encrypt(
                                key,
                                padding.OAEP(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )
                            data = handle_group_add_file(group_id, encrypted_content, encrypted_key)
                            encrypted_data = encrypt_data(data, self.shared_key)
                            self.writer.write(encrypted_data)
                            await self.writer.drain()
                            response = await self.reader.read(max_msg_size)
                            decrypted_response = aes_gcm.decipher(response, self.shared_key)
                            response = bson.loads(decrypted_response)
                            if response["status"] == "ok":
                                if "file_id" in response:
                                    file_id = response["file_id"]
                                    #checking if readers_keys is null or not 
                                    readers_keys = response.get("readers_keys", None)
                                    if not readers_keys:
                                        print(response["file_id"]["message"])
                                        continue
                                    encrypted_keys_for_readers = {}

                                    for readers, public_key_pem in readers_keys.items():
                                        user_public_key = serialization.load_pem_public_key(public_key_pem)
                                        encrypted_key_for_reader = user_public_key.encrypt(
                                            key,
                                            padding.OAEP(
                                                mgf=padding.MGF1(hashes.SHA256()),
                                                algorithm=hashes.SHA256(),
                                                label=None
                                            )
                                        )
                                        encrypted_keys_for_readers[readers] = encrypted_key_for_reader
                            
                                    response_data = bson.dumps({
                                        "status": "ok",
                                        "file_id": file_id,
                                        "readers_keys": {
                                            user_id: encrypted_key for user_id, encrypted_key in encrypted_keys_for_readers.items()
                                        }
                                    })

                                    encrypted_response_data = encrypt_data(response_data, self.shared_key)
                                    self.writer.write(encrypted_response_data)
                                    await self.writer.drain()
                                    final_response = await self.reader.read(max_msg_size)
                                    decrypted_final_response = aes_gcm.decipher(final_response, self.shared_key)
                                    final_response = bson.loads(decrypted_final_response)
                                    if final_response["status"] == "ok":
                                        print(final_response["file_id"]["message"])
                                    else:
                                        print("Error adding file to group:", final_response["message"])
                                else:
                                    print(response["file_id"]["message"])
                                    await self.writer.drain()
                            else:
                                print("Error adding file to group:", response["message"])
                        else:
                            print(f"File {file_path} does not exist. Please provide a valid file path.")
                    else:
                        print("Invalid group command")
                else:
                    print("Invalid group command")
            elif cmd == "help":
                print("Available commands:")
                print("add <file-path>") #feito
                print("list [-u user-id | -g group-id]") # feito
                print("read <file-id>") # feito
                print("share <file-id> <user-id> <permission>") #feito
                print("delete <file-id>") #feito
                print("replace <file-id> <file-path>") #feito
                print("details <file-id>") # feito 
                print("revoke <file-id> <user-id>") #feito
                print("group create <group name>") #feito
                print("group delete <group-id>") # feito
                print("group add-user <group-id> <user-id> <permissions>") #feito
                print("group delete-user <group-id> <user-id>")  #feito
                print("group list")
                print("group add <group-id> <file-path>") # feito
                print("exit") # feito

            else:
                print("Invalid command. Type 'help' for available commands.")

        except Exception as e:
            print(f"Error processing command: {e}")
        
        except (ConnectionResetError, asyncio.IncompleteReadError):
            print("\n🛑 Server connection lost. Closing client...")
            break

        except Exception as e:
            print(f"Error processing command: {e}")
     if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            print("Connection closed.")

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("p12_file", help="Name of client PKCS12 file")
    args = parser.parse_args()

    client = Client(args.p12_file)
    client.reader, client.writer = await asyncio.open_connection('127.0.0.1', conn_port)
    
    if await client.authenticate():
        print("\nAuthentication successful! You can now enter commands.")
        print("Type 'help' for available commands.\n")
        await client.command_loop()
    else:
        print("Authentication failed")

    client.writer.close()
    await client.writer.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())