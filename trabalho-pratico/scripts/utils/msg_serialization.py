import bson
from typing import Dict, List, Union
from enum import Enum

def mkpair(x, y):
    """ Produz uma byte-string contendo o tuplo '(x,y)' ('x' e 'y' são byte-strings) """
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, 'little')
    return len_x_bytes + x + y


def unpair(xy):
    """ Extrai componentes de um par codificado com 'mkpair' """
    len_x = int.from_bytes(xy[:2], 'little')
    x = xy[2:len_x+2]
    y = xy[len_x+2:]
    return x, y


class Permission(Enum):
    READ = 'r'
    WRITE = 'w'
    EXECUTE = 'x'


class MessageSerializer:
    @staticmethod
    def serialize_add(content: bytes, encrypted_key: bytes) -> bytes:
        """Serializa comando 'add'"""
        data = {
            'command': 'add',
            'content': content,
            'encrypted_key': encrypted_key
        }
        return bson.dumps(data)

    @staticmethod
    def serialize_list(user_id: str = None, group_id: str = None) -> bytes:
        """Serializa comando 'list'"""
        data = {'command': 'list'}
        if user_id:
            data['user_id'] = user_id
        if group_id:
            data['group_id'] = group_id
        return bson.dumps(data)

    @staticmethod
    def serialize_share(file_id: str, user_id: str, permissions: List[Permission]) -> bytes:
        """Serializa comando 'share'"""
        return bson.dumps({
            'command': 'share',
            'file_id': file_id,
            'user_id': user_id,
            'permissions': [p.value for p in permissions]
        })

    @staticmethod
    def serialize_delete(file_id: str) -> bytes:
        """Serializa comando 'delete'"""
        return bson.dumps({
            'command': 'delete',
            'file_id': file_id
        })

    @staticmethod
    def serialize_replace(file_id: str, content: bytes, encrypted_key: bytes) -> bytes:
        """Serializa comando 'replace'"""
        return bson.dumps({
            'command': 'replace',
            'file_id': file_id,
            'content': content,
            'encrypted_key': encrypted_key
        })

    @staticmethod
    def serialize_details(file_id: str) -> bytes:
        """Serializa comando 'details'"""
        return bson.dumps({
            'command': 'details',
            'file_id': file_id
        })

    @staticmethod
    def serialize_revoke(file_id: str, user_id: str) -> bytes:
        """Serializa comando 'revoke'"""
        return bson.dumps({
            'command': 'revoke',
            'file_id': file_id,
            'user_id': user_id
        })

    @staticmethod
    def serialize_read(file_id: str) -> bytes:
        """Serializa comando 'read'"""
        return bson.dumps({
            'command': 'read',
            'file_id': file_id
        })

    @staticmethod
    def serialize_group_create(group_name: str) -> bytes:
        """Serializa comando 'group create'"""
        return bson.dumps({
            'command': 'group_create',
            'group_name': group_name
        })

    @staticmethod
    def serialize_group_delete(group_id: str) -> bytes:
        """Serializa comando 'group delete'"""
        return bson.dumps({
            'command': 'group_delete',
            'group_id': group_id
        })

    @staticmethod
    def serialize_group_add_user(group_id: str, user_id: str, permissions: List[Permission]) -> bytes:
        """Serializa comando 'group add-user'"""
        return bson.dumps({
            'command': 'group_add_user',
            'group_id': group_id,
            'user_id': user_id,
            'permissions': [p.value for p in permissions]
        })

    @staticmethod
    def serialize_group_delete_user(group_id: str, user_id: str) -> bytes:
        """Serializa comando 'group delete-user'"""
        return bson.dumps({
            'command': 'group_delete_user',
            'group_id': group_id,
            'user_id': user_id
        })

    @staticmethod
    def serialize_group_list() -> bytes:
        """Serializa comando 'group list'"""
        return bson.dumps({'command': 'group_list'})

    @staticmethod
    def serialize_group_add(group_id: str, content: bytes, encrypted_key: bytes) -> bytes:
        """Serializa comando 'group add'"""
        return bson.dumps({
            'command': 'group_add',
            'group_id': group_id,
            'content': content,
            'encrypted_key': encrypted_key
        })
    @staticmethod
    def response_group_key_distribution(file_id,readers_keys: Dict ) -> bytes:
    
        return bson.dumps({
            'status': 'ok',
            'file_id': file_id,
            'readers_keys': readers_keys
        })
        
        

    @staticmethod
    def response_replace_key_distribution(user_id: str, readers_public_keys: dict) -> bytes:
        return bson.dumps({
            "status": "replace",
            "user_id": user_id,
            "readers_public_keys": readers_public_keys
        })




    @staticmethod
    def serialize_exit() -> bytes:
        """Serializa comando 'exit'"""
        return bson.dumps({'command': 'exit'})
    
    @staticmethod
    def serialize_encrypted_key(file_id: str, encrypted_keys: List[Dict[str, bytes]]) -> bytes:
        """Serializa as chaves encriptadas para cada utilizador"""
        return bson.dumps({
            'command': 'replace_encrypted_key',
            'file_id': file_id,
            'encrypted_keys': encrypted_keys
        })


    def serialize_response_group_key_distribution(data: dict) -> bytes:
        return bson.dumps({
            "status": "request",
            "user_id": data["user_id"],
            "readers_keys": {
                file_id: encrypted_key
                for file_id, encrypted_key in data["readers_keys"].items()
            },
            "target_pubkey": data["target_pubkey"]
        })



    @staticmethod
    def deserialize(data: bytes) -> Dict[str, Union[str, bytes, List[Permission]]]:
        """Deserializa qualquer mensagem"""
        msg = bson.loads(data)

        # Converter lista de permissões para Enum, se aplicável
        if 'permissions' in msg:
            msg['permissions'] = [Permission(p) for p in msg['permissions']]

        return msg

    # Respostas do servidor

    @staticmethod
    def response_ok(data: Dict[str, Union[str, bytes, List[str]]] = None) -> bytes:
        """Resposta de sucesso genérica"""
        response = {'status': 'ok'}
        if data:
            response.update(data)
        return bson.dumps(response)

    @staticmethod
    def response_error(message: str) -> bytes:
        """Resposta de erro"""
        return bson.dumps({
            'status': 'error',
            'message': message
        })

    @staticmethod
    def response_add_success(file_id: str) -> bytes:
        """Resposta ao comando 'add'"""
        return MessageSerializer.response_ok({'file_id': file_id})

    @staticmethod
    def response_list(files: List[Dict[str, str]]) -> bytes:
        """Resposta ao comando 'list'"""
        return MessageSerializer.response_ok({'files': files})

    @staticmethod
    def response_read(file_name: str, content: bytes, encrytped_key: bytes) -> bytes:
        """Resposta ao comando 'read'"""
        return MessageSerializer.response_ok({
            'file_name': file_name,
            'content': content,
            'encrypted_key': encrytped_key
        })

    @staticmethod
    def response_details(info: Dict[str, Union[str, List[Dict[str, str]]]]) -> bytes:
        """Resposta ao comando 'details'"""
        return MessageSerializer.response_ok(info)
    

    @staticmethod

    def response_share(user_id: str, encrypted_key: bytes  ,user_public_key:bytes) -> bytes:
        """Resposta ao comando 'share'"""
        return MessageSerializer.response_ok({
            'status': 'ok',
            'user_id': user_id,
            'encrypted': encrypted_key,
            'user_public_key': user_public_key
        })


    def response_share_success(message: str) -> bytes:
        """Resposta ao comando 'share'"""
        return MessageSerializer.response_ok({'message': message})

    @staticmethod
    def response_group_create_success(group_id: str) -> bytes:
        """Resposta ao comando 'group create'"""
        return MessageSerializer.response_ok({'group_id': group_id})

    @staticmethod
    def response_group_list(groups: List[Dict[str, Union[str, List[str]]]]) -> bytes:
        """Resposta ao comando 'group list'"""
        return MessageSerializer.response_ok({'groups': groups})

    @staticmethod
    def response_file_permission_error(file_id: str) -> bytes:
        """Erro ao tentar ler ou acessar um ficheiro sem permissões"""
        return MessageSerializer.response_error(f"Acesso negado ao ficheiro '{file_id}'")

    @staticmethod
    def response_not_found(entity: str, id: str) -> bytes:
        """Erro genérico ao não encontrar um ficheiro ou grupo"""
        return MessageSerializer.response_error(f"{entity} com ID '{id}' não encontrado.")
    
    @staticmethod
    def response_replace(file_id: str, users_with_public_keys: List[Dict[str, Union[str, bytes]]]) -> bytes:
        """Resposta ao comando 'replace' com utilizadores e chaves públicas"""
        return bson.dumps({
            'status': 'ok',
            'file_id': file_id,
            'users_with_public_keys': users_with_public_keys
        })

