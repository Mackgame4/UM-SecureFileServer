from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import bson

# # Supõe que leste isto da tua "base de dados":
# chave_pem_str = '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxgjYnr1d5qDDSUcqTow9\nFO4ezyO/0F/opsvm1Ywp6lYhdCXeWOMeq9nWP4ypIOslQdHD67BBssSMwMNnHLHj\n7YzFhB9xdIZHw/o77/XxbnNey2B+AQ/M1VaEZrhsRygxCFXTaUtbMMoZenBoQmYL\nmDor+WyByFwuZihhpw0DlkNsU8VEW3Af4iFeck5PTY0x+YYix/YIOvx/0NI0gmLD\ndMqrlf7fALlPkwcE2N4+lvUiyJNaCm+lozYqXuDOWfCa5FhIpAreuGafTHHX/CcJ\nYSNuNXDKV7Klt0IhGnWmb/Iakn3SloJ8ALb77ybpL45FKJ3q1fr8gZcXR/8dCE23\nrwIDAQAB\n-----END PUBLIC KEY-----\n'

# # Converte para bytes
# chave_pem_bytes = chave_pem_str.encode()
# print("Chave PEM em bytes:", chave_pem_bytes)

# # Carrega a chave pública
# public_key = serialization.load_pem_public_key(chave_pem_bytes)
# print (public_key)

# # Encripta algo
# mensagem = b"segredo top"
# cifrado = public_key.encrypt(
#     mensagem,
#     padding.OAEP(
#         mgf=padding.MGF1(hashes.SHA256()),
#         algorithm=hashes.SHA256(),
#         label=None
#     )
# )
# print("Mensagem encriptada:", cifrado.hex())


data = {'file_id': 'Group_277f.txt', 'readers_keys': {'VAULT_CLI2': b'\xaf|\xf1\xcb\xfe\xfb59\x99f\xc0E8K=\xa8\x12\xcd\x7f\xab~\xbbf\xb0Y\x87K\x82|U\xbf\xb6P\x7fkh\xc7r\x80\x08\xfc\x95C\xe8\x0c\xc8\xe7T\xc4\xd8>Z V\xb0a\xb8^\x83\xa5\xbc\x7f\x15\x12Ko\x9bW24.OW5e\x05\xeeh\xcd\x1b\xb6\xb3K*9\x04\xa1T;j\xc20\xaa\x92Z\xa1\xdf\xf0`\x8c\xae\xe0\xeaj+\x7f\xa4\xbf\x98k\xd6e\xf3\xe1Vf\xc8\x90\xd7\xb5\xbc0<\xa7\xccB\xce\x8a\x9a\xbb<\x8fv\x0c\x1eF\xf24\xed\xf7\x87\x97pf\x9a\xcf\xbc@\xe4kK:\x16\xe4\xe3\xad\x1b\xff|\xf8\xcd\xba\xb4\x18\x9e\xb8\xf9\xc4G\x8a;\xb3m+Th/\xa3KZ\xce\xd3\x1f\xebR\x9d\xfc9^\xf8\x19*\xe8U\xa2\x03\x04\xecj\xd44\x0e[F;\xb4\xca\x15\xf5\xa6\x85\xcf\xa7b`U\x81\xbd\xf8\x1a\xba]\x06]lP\xdd\x80\xfa\x06R\x9d,\x143\xe6\xa5)\x1e\x97\xf8\x9c|6\x97\xa3\x9f4\x1d_C\xd8\x14\xb1\r\xc5'}}

response_data = bson.dumps({
                                        "status": "ok",
                                        "file_id": "arroz",
                                        "readers_keys": data
                                    })

# # Serializa o dicionário
print("Serialized data:", response_data)

# # Deserializa o dicionário
deserialized_data = bson.loads(response_data)
print("Deserialized data:", deserialized_data)

