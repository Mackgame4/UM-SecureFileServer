import asyncio
import os
import bson
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from utils.msg_serialization import mkpair, unpair,MessageSerializer, Permission
from cryptography.hazmat.primitives import serialization
from utils.validate_cert import valida_cert
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import utils.aes_gcm as aes_gcm
import uuid
import logging

conn_port = 8443
max_msg_size = 9999
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
db_lock = asyncio.Lock()
personal_files_dir = "Vault/Personal/"
group_files_dir = "Vault/Groups/"
base_dir = os.path.dirname(os.path.abspath(__file__))

database = None
database_key = None
def encrypt_data(data, key):
    encrypted_data = aes_gcm.cipher(data, key)
    return encrypted_data

def load_database_key():
    # open from the certificate file
    p12_path = os.path.join(base_dir, "../projCA/VAULT_SERVER.p12")
    with open(p12_path, "rb") as p12_file:
        private_key, cert, _ = pkcs12.load_key_and_certificates(
            p12_file.read(), password=None
        )
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'database encryption key',
        backend=default_backend()
    )

    database_key = hkdf.derive(private_key_bytes)
   # print(f"Database key derived successfully: {database_key.hex()}")
    return database_key



def load_database():
    """Carrega a base de dados do ficheiro encriptado"""
    global database
    global database_key

    # Load the database key from the certificate
    database_key = load_database_key()

    if not os.path.exists("database.bson"):
        print("Database file not found, creating new one...")
        default_db = {"users": {}, "groups": {}}
        save_database(default_db)

        # Define permissões 700 no arquivo criado
        os.chmod("database.bson", 0o700)
        database = default_db
        return default_db

    try:
        with open("database.bson", "rb") as file:
            encrypted_data = file.read()
            bson_data = aes_gcm.decipher(encrypted_data, database_key)
            database = bson.loads(bson_data)
            return database
    except Exception as e:
        print(f"Error loading database: {e}")
        return {"users": {}, "groups": {}}

def save_database(data=None):
    """Salva a base de dados encriptada no ficheiro"""
    global database
    global database_key
    if data is None:
        data = database

    try:
        bson_data = bson.dumps(data)
        encrypted_data = aes_gcm.cipher(bson_data, database_key)

        with open("database.bson", "wb") as file:
            file.write(encrypted_data)
        load_database()
    except Exception as e:
        print(f"Error saving database: {e}")


class ServerWorker:
    def __init__(self):
        # Load server credentials
        p12_path = os.path.join(base_dir, "../projCA/VAULT_SERVER.p12")
        with open(p12_path, "rb") as p12_file:
            self.private_key, self.cert, _ = pkcs12.load_key_and_certificates(
                p12_file.read(), password=None
            )
        self.nonce = os.urandom(16)

        # Generate DH key pair
        self.dh_private_key = dh.DHParameterNumbers(p, g).parameters().generate_private_key()
        self.dh_public_key = self.dh_private_key.public_key()
        self.shared_key = None
        self.private_files_id = 0

    import os

    async def store_personal_file(self,file_name, user_id, encrypted_key):
        """Armazena um ficheiro pessoal do cliente na base de dados"""
        global database
        async with db_lock:
            if user_id not in database["users"]:
                database["users"][user_id] = {
                    "public_key": None,
                    "personal_files": {},
                    "shared_with_me": {}
                }
            
            if "personal_files" not in database["users"][user_id]:
                database["users"][user_id]["personal_files"] = {}
            
            database["users"][user_id]["personal_files"][file_name] = {
                "name": file_name,  
                "key": encrypted_key
            }
            
            save_database()


    async def handle_client_requests(self,reader, writer):
        global database
        try:
            while True:
                # Step 7.1: Receive a command from the client
                command_data = await reader.read(max_msg_size)
                if not command_data:
                    break  # No data means the client disconnected

                decrypted_command = aes_gcm.decipher(command_data, self.shared_key)
                command = bson.loads(decrypted_command)
                
                cmd = command["command"]
                logging.info(f"Received command: {cmd} from {self.claimed_pseudonym}")
                if cmd == "exit":
                    print("Client requested to exit.")
                    await self.secure_terminate(writer, "Client exited")
                    break

                elif cmd == "add":
                    encrypted_content = command['content']
                    encrypted_key = command['encrypted_key']
                    new_id = str(uuid.uuid4().hex[:8])
                    new_file_name = self.claimed_pseudonym + "_" + new_id + ".txt"
                    new_file_dir = personal_files_dir + self.claimed_pseudonym + "/" + new_file_name
                    self.private_files_id += 1
                    with open(new_file_dir, "wb") as f:
                        f.write(encrypted_content)
                    os.chmod(new_file_dir,0o700)
                    await self.store_personal_file(new_file_name, self.claimed_pseudonym, encrypted_key)
                    sucess_response = MessageSerializer.response_add_success("The new file name in your personal Vault is: " + new_file_name)
                    encrypted_data = encrypt_data(sucess_response, self.shared_key)
                    writer.write(encrypted_data)
                    await writer.drain()

                elif cmd == "group_add":
                    try:
                        group_id = command['group_id']
                        content = command['content']
                        encrypted_key = command['encrypted_key']

                        if group_id not in database["groups"]:
                            raise FileNotFoundError("Group does not exist.")

                        group = database["groups"][group_id]

                        if self.claimed_pseudonym not in group["members"]:
                            raise PermissionError("You are not a member of this group. Please contact the group admin.")

                        user_perms = group["members"][self.claimed_pseudonym]
                        if "w" not in user_perms and self.claimed_pseudonym != group["admin"]:
                            raise PermissionError("You do not have permission to add files to this group.")

                        parts = group_id.split('_', 2)
                        group_name = parts[2] if len(parts) == 3 else "unknown"
                        file_id = "Group_" + f"{group_name}_" + str(uuid.uuid4().hex[:4]) + ".txt"

                        new_file_dir = group_files_dir + group_id + "/" + file_id 
                        with open(new_file_dir, "wb") as f:
                            f.write(content)
                        os.chmod(new_file_dir, 0o700)

                        
                        async with db_lock:
                            database["groups"][group_id]["files"][file_id] = {
                                "readers": {
                                    member: None for member, perms in group["members"].items() if "r" in perms
                                }
                            }
                            if "r" in database["groups"][group_id]["members"][self.claimed_pseudonym]:
                                database["groups"][group_id]["files"][file_id]["readers"][self.claimed_pseudonym] = encrypted_key
                            save_database()

                        
                        reader_pubkeys = {
                            reader: database["users"][reader]["public_key"]
                            for reader in database["groups"][group_id]["files"][file_id]["readers"]
                            if reader != self.claimed_pseudonym
                        }

                        if not reader_pubkeys:
                            response = MessageSerializer.response_add_success({
                                "message": "File added successfully to the group. The file ID is: " + file_id
                            })
                        
                            encrypted_response = encrypt_data(response, self.shared_key)
                            writer.write(encrypted_response)
                            await writer.drain()
                            continue
        
                        
                        response = MessageSerializer.response_group_key_distribution(file_id, reader_pubkeys)
                        encrypted_response = encrypt_data(response, self.shared_key)
                        writer.write(encrypted_response)
                        await writer.drain()

                        
                        data = await reader.read(max_msg_size)
                        decrypted_data = aes_gcm.decipher(data, self.shared_key)
                        parsed = bson.loads(decrypted_data)
                        encrypted_keys = parsed["readers_keys"]

                       
                        async with db_lock:
                            for user_id, encrypted_key in encrypted_keys.items():
                                if user_id in database["groups"][group_id]["files"][file_id]["readers"]:
                                    database["groups"][group_id]["files"][file_id]["readers"][user_id] = encrypted_key
                            save_database()

                       
                        success_response = MessageSerializer.response_add_success({
                            "message": "File added successfully to the group with ID:" + file_id
                        })
                        encrypted_data = encrypt_data(success_response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()

                    except (FileNotFoundError, PermissionError, KeyError, ValueError) as e:
                        error_response = MessageSerializer.response_error(str(e))
                        encrypted_data = encrypt_data(error_response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()

                    except Exception as e:
                        # Erros inesperados
                        error_response = MessageSerializer.response_error(str(e))
                        encrypted_data = encrypt_data(error_response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()





                elif cmd == "group_create":
                    try:
                        group_name = command["group_name"]

                        numeric_id = str(uuid.uuid4().int)[:4] 
                        group_id = f"Group_{numeric_id}_{group_name}"


                        async with db_lock:
                            if group_id in database["groups"]:
                                raise FileExistsError("Group ID already exists. Please try again.")

                           
                            database["groups"][group_id] = {
                                "name": group_name,
                                "admin": self.claimed_pseudonym,
                                "members": {
                                    self.claimed_pseudonym: ["r","w"]
                                },
                                "files": {}
                            }

                            group_folder_path = f"Vault/Groups/{group_id}"
                            os.makedirs(group_folder_path, exist_ok=True)
                            os.chmod(group_folder_path, 0o700)
                            save_database()

                        success_response = MessageSerializer.response_group_create_success("Group created successfully, ID: " + group_id)
                        encrypted_data = encrypt_data(success_response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()

                    except (FileExistsError, KeyError, OSError) as e:
                        error_response = MessageSerializer.response_error(str(e))
                        encrypted_data = encrypt_data(error_response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()


                elif cmd == "group_add_user":
                        try:
                            group_id = command['group_id']
                            user_id = command['user_id']
                            permissions = command['permissions']  # Lista de strings: "r", "w"

                            async with db_lock:
                                if group_id not in database["groups"]:
                                    raise PermissionError  # Não revelar se o grupo existe

                                group = database["groups"][group_id]

                                if self.claimed_pseudonym != group["admin"]:
                                    raise PermissionError  # Não revelar se o utilizador é admin ou não

                                if user_id not in database["users"]:
                                    raise FileNotFoundError("User does not exist.")

                                # Adicionar utilizador ao grupo com as permissões
                                # check if the person is already in the group
                                if user_id in group["members"]:
                                    raise FileExistsError("User already exists in the group.")
                                #
                                group["members"][user_id] = permissions

                                # Se não tiver permissão de leitura, terminar aqui
                                if "r" not in permissions:
                                    save_database()
                                    response = MessageSerializer.response_add_success(f"User {user_id} added to group.")
    
                                    encrypted_response = encrypt_data(response, self.shared_key)
                                    writer.write(encrypted_response)
                                    await writer.drain()
                                    return

                                # Preparar dicionário de chaves a reencriptar
                                files_to_encrypt = {}

                                for file_id, file_info in group["files"].items():
                                    # Se o ficheiro tiver chave disponível para o admin
                                    if self.claimed_pseudonym in file_info["readers"]:
                                        encrypted_key = file_info["readers"][self.claimed_pseudonym]
                                        files_to_encrypt[file_id] = encrypted_key

                                # Preparar resposta com a pubkey do novo user + chaves encriptadas para o admin
                                pubkey_new_user = database["users"][user_id]["public_key"]

                                response = MessageSerializer.serialize_response_group_key_distribution({
                                    "user_id": user_id,
                                    "readers_keys": {
                                        file_id: encrypted_key for file_id, encrypted_key in files_to_encrypt.items()
                                    },
                                    "target_pubkey": pubkey_new_user
                                })

                                encrypted_response = encrypt_data(response, self.shared_key)
                                writer.write(encrypted_response)
                                await writer.drain()

                                # Esperar pelas chaves reencriptadas
                                data = await reader.read(max_msg_size)
                                decrypted_data = aes_gcm.decipher(data, self.shared_key)
                                parsed = bson.loads(decrypted_data)

                                encrypted_keys = parsed["encrypted_keys"] 
                                for file_id, enc_key in encrypted_keys.items():
                                    group["files"][file_id]["readers"][user_id] = enc_key

                                save_database()

                                success_response = MessageSerializer.response_add_success(f"User {user_id} added to group.")
                                encrypted_data = encrypt_data(success_response, self.shared_key)
                                writer.write(encrypted_data)
                                await writer.drain()

                        except PermissionError:
                            error_response = MessageSerializer.response_error("Not possible to add person to this group. Group does not exist or you are not the admin.")
                            encrypted_data = encrypt_data(error_response, self.shared_key)
                            writer.write(encrypted_data)
                            await writer.drain()

                        except Exception as e:
                            error_response = MessageSerializer.response_error({e})
                            encrypted_data = encrypt_data(error_response, self.shared_key)
                            writer.write(encrypted_data)
                            await writer.drain()





                
                elif cmd == "read":
                    user_id = self.claimed_pseudonym
                    file_id = command.get("file_id")

                    try:
                        if user_id not in database["users"]:
                            raise FileNotFoundError("User not found.")

                        file_path, file_name, encrypted_key = None, None, None

                        if file_id in database["users"][user_id]["personal_files"]:
                            info = database["users"][user_id]["personal_files"][file_id]
                            file_name = info["name"]
                            encrypted_key = info["key"]
                            file_path = f"{personal_files_dir}{user_id}/{file_name}"

                        elif file_id in database["users"][user_id]["shared_with_me"]:
                            info = database["users"][user_id]["shared_with_me"][file_id]
                            if "r" not in info["perms"]:
                                raise PermissionError("You don't have permission to read this shared file.")
                            owner = info["owner"]
                            file_name = database["users"][owner]["personal_files"][file_id]["name"]
                            encrypted_key = info["key"]
                            file_path = f"{personal_files_dir}{owner}/{file_name}"

                        else:
                            group_id = next(
                                (gid for gid, g in database["groups"].items() if file_id in g["files"] and user_id in g["files"][file_id]["readers"]),
                                None
                            )
                            if not group_id:
                                raise PermissionError("You don't have permission to read this file,or it doesn't exist. Please contact the admin and check the file ID.")
                            encrypted_key = database["groups"][group_id]["files"][file_id]["readers"][user_id]
                            file_name = file_id
                            file_path = f"{group_files_dir}{group_id}/{file_id}"

                        with open(file_path, "rb") as f:
                            content = f.read()

                        response = MessageSerializer.response_read(file_name, content, encrypted_key)
                        encrypted_data = encrypt_data(response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()

                    except (FileNotFoundError, PermissionError) as e:
                        error_response = MessageSerializer.response_error(str(e))
                        encrypted_data = encrypt_data(error_response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()

                    except Exception as e:
                        error_response = MessageSerializer.response_error(str(e))
                        encrypted_data = encrypt_data(error_response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()







                elif cmd == "share":
                    try:
                        file_id = command['file_id']
                        user_id = command['user_id']
                        permissions = command['permissions']

                        print(f"Permissions: {permissions}")

                        if file_id in database["users"][self.claimed_pseudonym]["personal_files"]:
                            if user_id not in database["users"]:
                                raise FileNotFoundError("User not found. Please share the file with a valid user.")

                            if "shared_with_me" not in database["users"][user_id]:
                                database["users"][user_id]["shared_with_me"] = {}

                            if file_id in database["users"][user_id]["shared_with_me"]:
                                raise FileExistsError("File already shared with this user.")

                            async with db_lock:
                                database["users"][user_id]["shared_with_me"][file_id] = {
                                    "owner": self.claimed_pseudonym,
                                    "key": None,
                                    "perms": permissions
                                }

                            if 'r' in permissions:
                                file_info = database["users"][self.claimed_pseudonym]["personal_files"][file_id]
                                encrypted_key = file_info["key"]
                                user_public_key = database["users"][user_id]["public_key"]

                                # Enviar a encrypted_key e a public key do utilizador
                                response = MessageSerializer.response_share(user_id, encrypted_key, user_public_key)
                                encrypted_response = encrypt_data(response, self.shared_key)
                                writer.write(encrypted_response)
                                await writer.drain()

                                new_encrypted_key_data = await reader.read(max_msg_size)
                                new_encrypted_key = aes_gcm.decipher(new_encrypted_key_data, self.shared_key)

                                async with db_lock:
                                    if file_id in database["users"][user_id]["shared_with_me"]:
                                        database["users"][user_id]["shared_with_me"][file_id]["key"] = new_encrypted_key
                                    else:
                                        raise FileNotFoundError("File not found in shared files.")

                            save_database()

                            success_response = MessageSerializer.response_ok({"message": "File shared successfully with user."})
                            encrypted_success = encrypt_data(success_response, self.shared_key)
                            writer.write(encrypted_success)
                            await writer.drain()

                        else:
                            raise PermissionError("The file you are trying to share is not in your personal files. Please check the file ID and try again.")

                    except (FileNotFoundError, PermissionError, FileExistsError) as e:
                        error_response = MessageSerializer.response_error(str(e))
                        encrypted_data = encrypt_data(error_response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()
                

                elif cmd == "replace":
                    file_id = command["file_id"]
                    content = command["content"]
                    new_encrypted_key = command["encrypted_key"]
                    user_id = self.claimed_pseudonym

                    try:
                        is_owner = False
                        owner_id = None
                        readers_to_notify = {}
                        group_id = None

                        async with db_lock:
                            if user_id in database["users"]:
                                # Caso o utilizador seja o dono do ficheiro
                                if file_id in database["users"][user_id]["personal_files"]:
                                    is_owner = True
                                    owner_id = user_id
                                    file_name = database["users"][user_id]["personal_files"][file_id]["name"]
                                    file_path = personal_files_dir + user_id + "/" + file_name

                                    # Atualiza a chave no ficheiro pessoal
                                    database["users"][user_id]["personal_files"][file_id]["key"] = new_encrypted_key

                                    # Descobre quem tem este ficheiro partilhado e precisa ser notificado
                                    for uid, user_data in database["users"].items():
                                        if file_id in user_data.get("shared_with_me", {}):
                                            perms = user_data["shared_with_me"][file_id]["perms"]
                                            if "r" in perms:  # Só notifica os leitores
                                                readers_to_notify[uid] = user_data["public_key"]

                                # Caso o utilizador tenha permissão de escrita no ficheiro partilhado
                                elif file_id in database["users"][user_id]["shared_with_me"]:
                                    perms = database["users"][user_id]["shared_with_me"][file_id]["perms"]
                                    if "w" not in perms:
                                        raise PermissionError("You don't have write access to this file.")

                                    owner_id = database["users"][user_id]["shared_with_me"][file_id]["owner"]
                                    file_name = database["users"][owner_id]["personal_files"][file_id]["name"]
                                    file_path = personal_files_dir + owner_id + "/" + file_name

                                    # Se também tiver permissão de leitura, atualiza a chave
                                    if "r" in perms:
                                        database["users"][user_id]["shared_with_me"][file_id]["key"] = new_encrypted_key

                                    # Adiciona o dono como destinatário obrigatório
                                    readers_to_notify[owner_id] = database["users"][owner_id]["public_key"]

                                    # E todos os outros leitores
                                    for uid, user_data in database["users"].items():
                                        if file_id in user_data.get("shared_with_me", {}):
                                            their_perms = user_data["shared_with_me"][file_id]["perms"]
                                            if "r" in their_perms:
                                                readers_to_notify[uid] = user_data["public_key"]
                                # Caso o ficheiro pertença a um grupo
                                else:
                                    for groups_id, group_data in database["groups"].items():
                                        if file_id in group_data.get("files", {}):
                                            if user_id not in group_data["members"] or "w" not in group_data["members"][user_id]:
                                                print(group_data["members"][user_id])
                                                raise PermissionError("You don't have write access to this group file.")

                                            file_path = group_files_dir  + groups_id + "/" + file_id
                                            owner_id = database["groups"][groups_id]["admin"]

                                            #checking if user has r permission so i can add the key to readers
                                            if "r" in group_data["members"][user_id]:
                                                database["groups"][groups_id]["files"][file_id]["readers"][user_id] = new_encrypted_key

                                            for reader_uid in group_data["files"][file_id]["readers"]:
                                                if reader_uid != user_id:
                                                    readers_to_notify[reader_uid] = database["users"][reader_uid]["public_key"]
                                            
                                            group_id = groups_id
                                            break
                                    if group_id is None:
                                        raise FileNotFoundError("File not found in personal files, shared files, or group files. Please verify the file ID.")

                        # Escreve o novo conteúdo no ficheiro
                        with open(file_path, "wb") as f:
                            f.write(content)

                        # Envia a resposta de distribuição de chaves (apenas com as chaves públicas)
                        response = MessageSerializer.response_replace_key_distribution(
                            user_id=user_id,
                            readers_public_keys=readers_to_notify
                        )

                        # Encripta a resposta e envia para o cliente
                        encrypted_data = encrypt_data(response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()

                        # Espera pela resposta do cliente (chaves encriptadas)
                        encrypted_response = await reader.read(max_msg_size)
                        decrypted_response = aes_gcm.decipher(encrypted_response, self.shared_key)
                        response = bson.loads(decrypted_response)

                        if "readers_public_keys" not in response:
                            raise ValueError("Missing encrypted_keys in response")

                        encrypted_keys_dict = response["readers_public_keys"]



                            # Atualiza as chaves encriptadas no banco de dados
                        async with db_lock:
                            if group_id is None:
                                for uid, encrypted_key in encrypted_keys_dict.items():
                                    if uid in database["users"]:
                                        if file_id in database["users"][uid]["shared_with_me"]:
                                            database["users"][uid]["shared_with_me"][file_id]["key"] = encrypted_key
                                        elif uid == owner_id:
                                            database["users"][uid]["personal_files"][file_id]["key"] = encrypted_key
                                    else:
                                        raise FileNotFoundError(f"User {uid} not found.")
                            else:
                                for uid, encrypted_key in encrypted_keys_dict.items():
                                    if uid in database["groups"][group_id]["files"][file_id]["readers"]:
                                        database["groups"][group_id]["files"][file_id]["readers"][uid] = encrypted_key


                        final_resp = MessageSerializer.response_add_success(f"The file content was replaced successfully for {file_id}.")
                        encrypted_final = encrypt_data(final_resp, self.shared_key)
                        writer.write(encrypted_final)
                        await writer.drain()

                    except (FileNotFoundError, PermissionError) as e:
                        error_response = MessageSerializer.response_error(str(e))
                        encrypted_data = encrypt_data(error_response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()


                elif cmd == "delete":
                    try:
                        file_id = command["file_id"]
                        user_id = self.claimed_pseudonym

                        # Personal File
                        if file_id in database["users"][user_id]["personal_files"]:
                            file_info = database["users"][user_id]["personal_files"].pop(file_id)
                            file_path = personal_files_dir + user_id + "/" + file_info["name"]

                            if os.path.exists(file_path):
                                os.remove(file_path)

                            async with db_lock:
                                for other_user in database["users"].values():
                                    other_user["shared_with_me"].pop(file_id, None)
                                save_database()

                            response = MessageSerializer.response_add_success({"message": "File deleted successfully."})

                        elif file_id in database["users"][user_id]["shared_with_me"]:
                            async with db_lock:
                                database["users"][user_id]["shared_with_me"].pop(file_id)
                                save_database()

                            response = MessageSerializer.response_add_success({"message": "Access to shared file removed."})

                        else:
                            found = False
                            for gid, group in database["groups"].items():
                                if file_id in group["files"]:
                                    found = True

                                    if group["admin"] != user_id:
                                        raise PermissionError("You don't have permission to delete this group file.")

                                    file_path = group_files_dir + gid + "/" + file_id
                                    if os.path.exists(file_path):
                                        os.remove(file_path)

                                    async with db_lock:
                                        group["files"].pop(file_id)
                                        save_database()

                                    response = MessageSerializer.response_add_success({"message": "Group file deleted successfully."})
                                    break

                            if not found:
                                raise FileNotFoundError("File not found.")

                    except (FileNotFoundError, PermissionError) as e:
                        response = MessageSerializer.response_error(str(e))

                    encrypted_data = encrypt_data(response, self.shared_key)
                    writer.write(encrypted_data)
                    await writer.drain()


                elif cmd == "revoke":
                    try:
                        file_id = command["file_id"]
                        target_user = command["user_id"]
                        owner_id = self.claimed_pseudonym

                        
                        if file_id not in database["users"][owner_id]["personal_files"]:
                            raise PermissionError("You can only revoke access to files you own.")

                        async with db_lock:
                            
                            if target_user in database["users"]:
                                database["users"][target_user]["shared_with_me"].pop(file_id, None)
                                save_database()
                            else:
                                raise FileNotFoundError("Target user not found.")

                        response = MessageSerializer.response_add_success({"message": "Access revoked successfully."})

                    except (PermissionError, FileNotFoundError) as e:
                        response = MessageSerializer.response_error(str(e))

                    encrypted_data = encrypt_data(response, self.shared_key)
                    writer.write(encrypted_data)
                    await writer.drain()

                elif cmd == "group_delete_user":
                    try:
                        group_id = command["group_id"]
                        target_user = command["user_id"]
                        requester = self.claimed_pseudonym

                        if group_id not in database["groups"]:
                            raise FileNotFoundError("Group does not exist.")

                        group = database["groups"][group_id]

                        if group["admin"] != requester:
                            raise PermissionError("Something went wrong. The group does not exist or you are not the admin.")

                        async with db_lock:

                            for file_info in group["files"].values():
                                file_info["readers"].pop(target_user, None)
                            group["members"].pop(target_user, None)

                            save_database()

                        response = MessageSerializer.response_add_success({"message": f"User {target_user} removed from group {group_id}."})

                    except (FileNotFoundError, PermissionError, ValueError) as e:
                        response = MessageSerializer.response_error(str(e))

                    encrypted_data = encrypt_data(response, self.shared_key)
                    writer.write(encrypted_data)
                    await writer.drain()

                elif cmd == "group_delete":
                    try:
                        group_id = command["group_id"]
                        requester = self.claimed_pseudonym

                        async with db_lock:
                            if group_id not in database["groups"]:
                                raise FileNotFoundError("Group does not exist.")

                            group = database["groups"][group_id]

                            if group["admin"] != requester:
                                raise PermissionError("The group does not exist or you are not the admin.")

                            # Remover ficheiros do sistema
                            group_folder = group_files_dir + group_id + "/"
                            if os.path.exists(group_folder):
                                for fname in os.listdir(group_folder):
                                    os.remove(os.path.join(group_folder, fname))
                                os.rmdir(group_folder)

                            del database["groups"][group_id]
                            save_database()

                        response = MessageSerializer.response_add_success({"message": f"Group {group_id} deleted successfully."})

                    except (FileNotFoundError, PermissionError) as e:
                        response = MessageSerializer.response_error(str(e))

                    encrypted_data = encrypt_data(response, self.shared_key)
                    writer.write(encrypted_data)
                    await writer.drain()

                elif cmd == "details":
                    try:
                        file_id = command["file_id"]
                        user_id = self.claimed_pseudonym

                        msg = ""
                        # --- Personal file ---
                        if file_id in database["users"][user_id]["personal_files"]:
                            file_info = database["users"][user_id]["personal_files"][file_id]
                            msg += f"📄 Name: {file_info['name']}\n"
                            msg += f"👤 Owner: {user_id}\n"
                            msg += f"🔐 Type: Personal file\n"

                            shared_with = []
                            for other_user_id, other_user_data in database["users"].items():
                                if other_user_id == user_id:
                                    continue
                                if file_id in other_user_data.get("shared_with_me", {}):
                                    perms = other_user_data["shared_with_me"][file_id]["permissions"]
                                    shared_with.append((other_user_id, perms))

                            if shared_with:
                                msg += "🤝 Shared with:\n"
                                for uid, perms in shared_with:
                                    msg += f"  - {uid}: {', '.join(perms)}\n"
                            else:
                                msg += "🤝 Shared with: No one\n"


                            response = MessageSerializer.response_add_success({"message": msg})
                        
                        elif file_id in database["users"][user_id]["shared_with_me"]:
                            file_info = database["users"][user_id]["shared_with_me"][file_id]
                            msg += f"📄 Name: {file_id}\n"
                            msg += f"🔐 Type: Shared file\n"
                            msg += f"🧾 Your permissions: {', '.join(file_info['perms'])}\n"
                            response = MessageSerializer.response_add_success({"message": msg})
    


                        # --- Group file ---
                        else:
                            found = False
                            for gid, group in database["groups"].items():
                                if file_id in group["files"]:
                                    found = True
                                    if user_id not in group["members"]:
                                        raise PermissionError("You are not a member of this group.")

                                    file_info = group["files"][file_id]
                                    msg += f"📄 Name: {file_id}\n"
                                    msg += f"👥 Group: {gid}\n"
                                    msg += f"👑 Admin: {group['admin']}\n"
                                    msg += f"🔐 Type: Group file\n"
                                    msg += f"🧾 Your permissions: {', '.join(group['members'][user_id])}\n"

                                    if user_id == group["admin"]:
                                        msg += "📜 Members and permissions:\n"
                                        for member, perms in group["members"].items():
                                            msg += f"  - {member}: {', '.join(perms)}\n"

                                    response = MessageSerializer.response_add_success({"message": msg})
                                    break

                            if not found:
                                raise FileNotFoundError("File not found.")

                    except (FileNotFoundError, PermissionError) as e:
                        response = MessageSerializer.response_error(str(e))

                    encrypted_data = encrypt_data(response, self.shared_key)
                    writer.write(encrypted_data)
                    await writer.drain()


                elif cmd == "list":
                    user_id = command.get("user_id", None)
                    group_id = command.get("group_id", None)
                    print (command)
                    print (user_id)
                    print (group_id)
                    print(database["users"][self.claimed_pseudonym])

                    try:
                        msg = ""

                        # Caso 1: list -u <user_id>
                        if user_id:
                            if user_id not in database["users"]:
                                raise ValueError("User not found.")

                            shared_files = database["users"][self.claimed_pseudonym].get("shared_with_me", {})
                            found = False
                            for file_id, file_info in shared_files.items():
                                if file_info["owner"] == user_id:
                                    found = True
                                    msg += f"📄 File ID: {file_id}\n"
                                    msg += f"👤 Owner: {user_id}\n"
                                    msg += f"🔐 Type: Shared file\n"
                                    msg += f"🧾 Your permissions: {', '.join(file_info['perms'])}\n\n"

                            if not found:
                                msg = f"No files shared with you by user '{user_id}'."

                        # Caso 2: list -g <group_id>
                        elif group_id:
                            group = database["groups"].get(group_id)
                            if not group or self.claimed_pseudonym not in group["members"]:
                                raise PermissionError("Group not found or you are not a member.")

                            msg += f"👥 Group: {group_id}\n"
                            msg += f"👑 Admin: {group['admin']}\n"
                            msg += f"🔐 Your permissions: {', '.join(group['members'][self.claimed_pseudonym])}\n"

                            if not group["files"]:
                                msg += "📁 No files in this group.\n"
                            else:
                                msg += "📄 Files:\n"
                                for file_id, file_info in group["files"].items():
                                    msg += f" File Name: {file_id}\n"

                        # Caso 3: list (sem argumentos)
                        else:
                            print("Listing all files")
                            msg += "📂 Accessible files:\n\n"
                            print (database["users"][self.claimed_pseudonym])

                            # Ficheiros pessoais
                            personal = database["users"][self.claimed_pseudonym].get("personal_files", {})
                            print (personal)
                            if personal:
                                msg += "🔒 Your personal files:\n"
                                for file_id, file_info in personal.items():
                                    msg += f"  - File Name :{file_id} (full access)\n"
                                msg += "\n"

                            # Ficheiros partilhados por outros
                            shared = database["users"][self.claimed_pseudonym].get("shared_with_me", {})
                            if shared:
                                msg += "🤝 Shared with you:\n"
                                for file_id, file_info in shared.items():
                                    msg += f"  - {file_id}: from {file_info['owner']} with perms {', '.join(file_info['perms'])}\n"
                                msg += "\n"

                            # Ficheiros de grupo
                            found_group = False
                            for gid, group in database["groups"].items():
                                if self.claimed_pseudonym in group["members"]:
                                    group_perms = group["members"][self.claimed_pseudonym]
                                    files = group.get("files", {})
                                    if files:
                                        found_group = True
                                        msg += f"👥 Group '{gid}' files:\n"
                                        for file_id, file_info in files.items():
                                            msg += f"  - Name : {file_id}  with perms {', '.join(group_perms)}\n"

                            if not personal and not shared and not found_group:
                                msg = "You don't have access to any files."
                            

                        response = MessageSerializer.response_add_success({"message": msg})
                        encrypted_data = encrypt_data(response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()

                    except Exception as e:
                        response = MessageSerializer.response_error(str(e))
                

                elif cmd == "group_list":
                    try:
                        msg = "📋 Your groups:\n\n"
                        found = False

                        for gid, group in database["groups"].items():
                            if self.claimed_pseudonym in group["members"]:
                                found = True
                                perms = group["members"][self.claimed_pseudonym]
                                msg += f"👥 Group ID: {gid}\n"
                                msg += f"🔐 Your permissions: {', '.join(perms)}\n"
                                msg += f"👑 Admin: {group['admin']}\n\n"

                        if not found:
                            msg = "You don't belong to any groups."

                        response = MessageSerializer.response_add_success({"message": msg})
                        encrypted_data = encrypt_data(response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()

                    except Exception as e:
                        response = MessageSerializer.response_error(str(e))
                        encrypted_data = encrypt_data(response, self.shared_key)
                        writer.write(encrypted_data)
                        await writer.drain()
            
            #closing the connection
            await self.secure_terminate(writer, "Client disconnected")



        except Exception as e:
            print(f"Error processing command: {e}")
            await self.secure_terminate(writer, "Error processing command")


    def get_client_identity(self, cert):
        """Extract the full client identity from certificate"""
        try:
            cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            pseudonym = cert.subject.get_attributes_for_oid(NameOID.PSEUDONYM)[0].value
            return pseudonym  
        except:
            return None

    async def store_client_public_key(self, user_id, public_key_pem):
        """Armazena a chave pública do cliente na base de dados e cria a pasta no servidor"""
        global database
        async with db_lock:
            if user_id not in database["users"]:
                
                database["users"][user_id] = {}
                database["users"][user_id]["public_key"] = None
                database["users"][user_id]["personal_files"] = {}
                database["users"][user_id]["shared_with_me"] = {}
                
                
            personal_dir = f"Vault/Personal/{user_id}"
            if not os.path.exists(personal_dir):
                os.makedirs(personal_dir, mode=0o700)
                print(f"Created personal directory for {user_id} at {personal_dir} with permissions 700")
                
            database["users"][user_id]["public_key"] = public_key_pem
            save_database()  

    def get_client_public_key(self, user_id):
        """Obtém a chave pública armazenada do cliente"""
        if user_id in database["users"]:
            return database["users"][user_id]["public_key"]
        return None

    async def handle_client(self, reader, writer):
        try:
            login_request = await reader.read(max_msg_size)
            self.claimed_pseudonym = login_request.decode().strip()
            print(f"Client claims to be: {self.claimed_pseudonym}")

            signed_nonce = self.private_key.sign(
                self.nonce,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            logging.info(f"Received login request from {self.claimed_pseudonym}")

            response = mkpair(
                self.nonce,
                mkpair(
                    signed_nonce,
                    self.cert.public_bytes(serialization.Encoding.PEM)
                )
            )
            writer.write(response)
            await writer.drain()

            # Step 3: Receive client response
            client_data = await reader.read(max_msg_size)
            client_sig, client_cert_pem = unpair(client_data)
            client_cert = x509.load_pem_x509_certificate(client_cert_pem)

            # Validate client identity
            actual_identity = self.get_client_identity(client_cert)
            client_num = self.claimed_pseudonym[-1]  # Gets the number from pseudonym
            expected_identity = f"User {client_num} (SSI Vault Client {client_num})"

            if not actual_identity or actual_identity != self.claimed_pseudonym:
                print(f"Expected: {self.claimed_pseudonym}, Actual: {actual_identity}")
                raise Exception("Certificate identity doesn't match claimed pseudonym")
                logging.info(f"Certificate identity doesn't match claimed pseudonym: {self.claimed_pseudonym} != {actual_identity}")

            if not valida_cert(client_cert, expected_identity):
                raise Exception("Invalid client certificate")

            # Verify signature
            try:
                client_cert.public_key().verify(
                    client_sig,
                    self.nonce,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except InvalidSignature:
                print("🛑 ALERT: Invalid signature - possible attack attempt!")
                logging.info("Invalid signature - possible attack attempt")
                await self.secure_terminate(writer, "Authentication failed: invalid signature")
                return
            except Exception as e:
                print(f"🛑 Unexpected verification error: {str(e)}")
                logging.info(f"Unexpected verification error: {str(e)}")
                await self.secure_terminate(writer, "Internal authentication error")
                return

            print(f"Successfully authenticated {actual_identity}")

            client_public_key_pem = client_cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # Store the client's public key and create the folder if needed
            print(self.claimed_pseudonym)
            await self.store_client_public_key(self.claimed_pseudonym, client_public_key_pem)

            # Step 4: Send DH public key to client along with auth success
            dh_public_bytes = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            #signing dh public key
            dh_public_key_signature = self.private_key.sign(
                dh_public_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Send the DH public key and signature to the client + auth success message
            auth_success_msg = mkpair(
                mkpair(
                    dh_public_bytes,
                    dh_public_key_signature
                ),
                b"AUTH_SUCCESS"
            )
            writer.write(auth_success_msg)
            await writer.drain()

            # Step 5: Receive client's DH public key
            client_dh_public_bytes = await reader.read(max_msg_size)
            client_dh_public_key, client_dh_sig = unpair(client_dh_public_bytes)

            #verifying the signature of the client if it is signing client_dh_public
            try:
                client_cert.public_key().verify(
                    client_dh_sig,
                    client_dh_public_key,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except InvalidSignature:
                print("🛑 ALERT: Invalid signature - possible attack attempt!")
                await self.secure_terminate()
                return False
            except Exception as e:
                print(f"🛑 Unexpected verification error: {str(e)}")
                await self.secure_terminate()
                return False

           


            # Step 6: Derive shared key
            client_dh_public_key = serialization.load_pem_public_key(client_dh_public_key)
            shared_key = self.dh_private_key.exchange(client_dh_public_key)

            # Perform key derivation
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)

            logging.info(f"Shared key derived for {self.claimed_pseudonym}, connection established.")
            await self.handle_client_requests(reader, writer)

        except Exception as e:
            print(f"Authentication failed: {e}")
            writer.write(b"AUTH_FAILED")
            await writer.drain()
        finally:
            writer.close()

    async def secure_terminate(self, writer, message):
        """Close connection securely with error message"""

        writer.write(message.encode())
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        save_database()
        print("Connection closed securely for client:", self.claimed_pseudonym)
        return


async def main():
    # creating directory called Vault if it doesn't exist with permissions 700
    if not os.path.exists("Vault"):
        os.makedirs("Vault", mode=0o700)
        # making dir Personal and Groups 
        os.makedirs("Vault/Personal", mode=0o700)
        os.makedirs("Vault/Groups", mode=0o700)
        print("Directory Vault created with permissions 700")
    else:
        print("Directory Vault already exists")

    # Load the database (this will initialize the global variable `database`)
    load_database()

    logging.basicConfig(
    filename='requests.log', 
    level=logging.INFO,       
    format='%(asctime)s - %(message)s', 
    )   
    log_file = 'requests.log'
    os.chmod(log_file, 0o700)

    server = await asyncio.start_server(
        lambda r, w: ServerWorker().handle_client(r, w),
        '127.0.0.1', conn_port
    )
    print(f'Serving on {conn_port}...')
    async with server:
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            print("Server stopped.")
            save_database()
            print("Database saved.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Server interrupted by user.")
        save_database()
        print("Database saved.")

