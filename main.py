import hashlib
import hmac
import base64
from pathlib import Path

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

def xmpp(username, password, client_nonce, intial_message, server_challenge, salt_b64, rounds):
    r_value = ""
    k = 0
    while server_challenge[k] != ",":
        r_value+=server_challenge[k]
        k+=1;
    client_final_message_bare = "c=biws,"+r_value
    salted_password = salted_sha1_PBKDF2(password.encode("utf-8"),bytes.fromhex(salt),rounds)
    #print("salted password =",salted_password)

    salt_client_key = "Client Key"
    client_key = hmac_sha1(bytes.fromhex(salted_password),salt_client_key.encode("utf-8"))
    #print("clientKey =",client_key)

    stored_key = sha1(bytes.fromhex(client_key))
    #print("sotredKey =",stored_key)

    auth_message = "n="+username+",r="+client_nonce+","+server_challenge+","+client_final_message_bare
    #print("auth message =",auth_message)

    client_signature = hmac_sha1(bytes.fromhex(stored_key), auth_message.encode("utf-8"))
    #print("client signature =",client_signature)

    client_proof = string_xor(client_key, client_signature)
    #print("client proof =",client_proof)

    """
    salt_server_key = "Server Key"
    server_key = hmac_sha1(bytes.fromhex(salted_password), salt_server_key.encode("utf-8"))
    #print("server key =",server_key)

    server_signature = hmac_sha1(bytes.fromhex(server_key), auth_message.encode("utf-8"))
    #print("server signature =",server_signature)
    """

    p_value = base64.b64encode(bytes.fromhex(client_proof)).decode("utf-8")
    client_final_message = client_final_message_bare+",p="+p_value
    #print("client final message =",client_final_message)

    return client_final_message

#User input
#password = "pencil"
initial_message = "n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL"
server_challenge = "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096"
client_final_message = "c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts="

wordlist = "~/files/wordlist/small_wordlist.txt"

wordlist = wordlist.replace("~", str(Path.home()))

w = open(wordlist,"r")

#parsing values from input
nonce_start=0
for i in range(len(initial_message)-1):
    if initial_message[i] == "r" and initial_message[i+1] == "=":
        nonce_start=i+2
client_nonce = initial_message[nonce_start:]
username_start=0
username_end=0
for i in range(len(initial_message)-1):
    if initial_message[i] == "n" and initial_message[i+1] == "=":
        username_start = i+2
    if initial_message[i] == ",":
        username_end = i
username = initial_message[username_start:username_end]

salt_start=0
salt_end=0
for i in range(len(server_challenge)-1):
    if server_challenge[i] == "s" and server_challenge[i+1] == "=":
        salt_start = i+2
    if server_challenge[i] == ",":
        salt_end = i
salt_b64 = server_challenge[salt_start:salt_end]
salt = base64.b64decode(salt_b64).hex()

s_rounds_start=0
k = len(server_challenge)-1
while server_challenge[k] != "=":
    s_rounds_start=k
    k-=1
rounds=int(server_challenge[s_rounds_start:])

#call to the xmpp function
for word in w:
    password = word.replace("\n","")
    res = xmpp(username, password, client_nonce, initial_message, server_challenge, salt_b64, rounds)
    if res == client_final_message:
        print("Mot de passe trouvé:",password)
