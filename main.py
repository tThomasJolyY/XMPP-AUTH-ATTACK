import hashlib
import hmac
import base64

def salted_sha1_PBKDF2(password, salt, rounds):
    # Appliquer PBKDF2-SHA-1
    salted_password = hashlib.pbkdf2_hmac('sha1', password, salt ,rounds)

    return salted_password.hex()

def hmac_sha1(key, message):
    hmac_sha1 = hmac.new(key, message, hashlib.sha1)

    # Retourner le résultat en hexadécimal
    return hmac_sha1.hexdigest()

import hashlib

def sha1(message):
    # Calculer le hash SHA-1
    sha1_hash = hashlib.sha1(message)

    # Retourner le résultat en hexadécimal
    return sha1_hash.hexdigest()

def string_xor(m1, m2):
    res =  int(m1,16) ^ int(m2,16)
    return '{:x}'.format(res)

#r=6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573,s=QSXCR+Q6sek8bf92,i=4096
"""
server_nonce = "6d442b5d9e51a740f369e3dcecf3178ec12b3985bbd4a8e6f814b422ab766573"
server_nonce_bytes = bytes.fromhex(server_nonce)

salt = "4125c247e43ab1e93c6dff76"
salt_bytes = bytes.fromhex(salt)
"""

username = "user"
password = "pencil"
client_nonce = "fyko+d2lbbFgONRv9qkxdawL"
initial_message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL"

server_nonce = "3rfcNHYJY1ZVvWVs7j"
server_challenge = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
salt_b64 = "QSXCR+Q6sek8bf92"
salt = base64.b64decode("QSXCR+Q6sek8bf92").hex()
rounds=4096

client_final_message_bare = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j"
salted_password = salted_sha1_PBKDF2(password.encode("utf-8"),bytes.fromhex(salt),rounds)
print("salted password =",salted_password)

salt_client_key = "Client Key"
client_key = hmac_sha1(bytes.fromhex(salted_password),salt_client_key.encode("utf-8"))
print("clientKey =",client_key)

stored_key = sha1(bytes.fromhex(client_key))
print("sotredKey =",stored_key)

auth_message = "n="+username+",r="+client_nonce+","+server_challenge+","+client_final_message_bare
print("auth message =",auth_message)

client_signature = hmac_sha1(bytes.fromhex(stored_key), auth_message.encode("utf-8"))
print("client signature =",client_signature)

client_proof = string_xor(client_key, client_signature)
print("client proof =",client_proof)

salt_server_key = "Server Key"
server_key = hmac_sha1(bytes.fromhex(salted_password), salt_server_key.encode("utf-8"))
print("server key =",server_key)

server_signature = hmac_sha1(bytes.fromhex(server_key), auth_message.encode("utf-8"))
print("server signature =",server_signature)

p_value = base64.b64encode(bytes.fromhex(client_proof)).decode("utf-8")
client_final_message = client_final_message_bare+",p="+p_value
print("client final message =",client_final_message)
