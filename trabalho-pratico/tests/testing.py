import bson
from msg_serialization import MessageSerializer, Permission

# Teste para serializar o comando 'add'
content = "viva o benfica"
encrypted_key = b"chave_encriptada"

serialized_add = MessageSerializer.serialize_add(content, encrypted_key)
print(f"Comando 'add' serializado (UTF-8): {serialized_add}")

# Teste para deserializar o comando 'add'
deserialized_add = MessageSerializer.deserialize(serialized_add)
print(f"\nComando 'add' deserializado: {deserialized_add}")

# Teste para serializar o comando 'list'
serialized_list = MessageSerializer.serialize_list(user_id="utilizador1")
print(f"\nComando 'list' serializado (UTF-8): {serialized_list.decode('utf-8')}")

# Teste para deserializar o comando 'list'
deserialized_list = MessageSerializer.deserialize(serialized_list)
print(f"\nComando 'list' deserializado: {deserialized_list}")

# Teste para serializar o comando 'replace'
file_id = "file123"
new_content = "Novo conteúdo do ficheiro".encode('utf-8')
serialized_replace = MessageSerializer.serialize_replace(file_id, new_content)
print(f"\nComando 'replace' serializado (UTF-8): {serialized_replace.decode('utf-8')}")

# Teste para deserializar o comando 'replace'
deserialized_replace = MessageSerializer.deserialize(serialized_replace)
print(f"\nComando 'replace' deserializado: {deserialized_replace}")

# Teste para serializar uma resposta de sucesso
response_ok = MessageSerializer.response_ok({"message": "Comando executado com sucesso"})
print(f"\nResposta de sucesso serializada (UTF-8): {response_ok.decode('utf-8')}")

# Teste para deserializar uma resposta de sucesso
deserialized_response_ok = MessageSerializer.deserialize(response_ok)
print(f"\nResposta de sucesso deserializada: {deserialized_response_ok}")
