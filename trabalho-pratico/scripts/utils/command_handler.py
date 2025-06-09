from utils.msg_serialization import MessageSerializer

def handle_exit():
    """Processa o comando 'exit'"""
    serialized = MessageSerializer.serialize_exit()
    return True  # Retorna True para indicar que o loop deve terminar

def handle_add(encrypted_content,encrypted_key):
    """Processa o comando 'add'"""
    
    serialized = MessageSerializer.serialize_add(encrypted_content, encrypted_key)
    return serialized

def handle_list(user_id=None, group_id=None):
    """Processa o comando 'list'"""
    serialized = MessageSerializer.serialize_list(user_id, group_id)
    return serialized

def handle_read(file_id):
    """Processa o comando 'read'"""
    serialized = MessageSerializer.serialize_read(file_id)
    return serialized

def handle_share(file_id, user_id, permissions):
    """Processa o comando 'share'"""
    serialized = MessageSerializer.serialize_share(file_id, user_id, permissions)
    return serialized

def handle_delete(file_id):
    """Processa o comando 'delete'"""
    serialized = MessageSerializer.serialize_delete(file_id)
    return serialized

def handle_replace(file_id, encrypted_content,encrypted_key):
    """Processa o comando 'replace'"""
    serialized = MessageSerializer.serialize_replace(file_id, encrypted_content, encrypted_key)
    return serialized

def handle_details(file_id):
    """Processa o comando 'details'"""
    serialized = MessageSerializer.serialize_details(file_id)
    return serialized

def handle_revoke(file_id, user_id):
    """Processa o comando 'revoke'"""
    serialized = MessageSerializer.serialize_revoke(file_id, user_id)
    return serialized

def handle_group_create(group_name):
    """Processa o comando 'group create'"""
    serialized = MessageSerializer.serialize_group_create(group_name)
    return serialized

def handle_group_delete(group_id):
    """Processa o comando 'group delete'"""
    serialized = MessageSerializer.serialize_group_delete(group_id)
    return serialized

def handle_group_add_user(group_id, user_id, permissions):
    """Processa o comando 'group add-user'"""
    serialized = MessageSerializer.serialize_group_add_user(group_id, user_id, permissions)
    return serialized

def handle_group_delete_user(group_id, user_id):
    """Processa o comando 'group delete-user'"""
    serialized = MessageSerializer.serialize_group_delete_user(group_id, user_id)
    return serialized

def handle_group_list():
    """Processa o comando 'group list'"""
    serialized = MessageSerializer.serialize_group_list()
    return serialized
def handle_group_add_file(group_id, encrypted_content, encrypted_key):
    """Processa o comando 'group add'"""
    serialized = MessageSerializer.serialize_group_add(group_id, encrypted_content, encrypted_key)
    return serialized
