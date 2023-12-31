import json
import socket
import threading
import pickle
import os
import sys
import ast
from Crypto.Cipher import AES

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pgpy import PGPKey
from hyper import (Hyper, pgpy_decrypt, pgpy_encrypt)
import pgpy
import base64

USER_CREDENTIALS_FILE = "user_credentials.txt"
USER_info_FILE = "user_info.txt"
USER_PROJECTS_FILE = "user_projects.txt"
user_credentials = {}
state = {}
session = {}
global private_key
private_key = None
client_public_keys = {}
global client_count
client_count = 0

def load_user_credentials():
    if os.path.exists(USER_CREDENTIALS_FILE):
        with open(USER_CREDENTIALS_FILE, "r") as file:
            lines = file.readlines()
            for line in lines:
                username, password, id_number, userRole = line.strip().split(":")
                user_credentials[username] = {'password': password, 'id_number': id_number , 'userRole':userRole}


def load_or_generate_private_key():
    global private_key
    hyper = Hyper()
    try:
        # Load private key
        with open("server_private_key.asc", "r") as f:
            private_key, _ = pgpy.PGPKey.from_file(f)
    except Exception as e:
        print(f"Error loading private key: {e}")
        private_key = hyper.pgp('server_')


def save_user_credentials():
    with open(USER_CREDENTIALS_FILE, "w") as file:
        #  for username, password,id_number in user_credentials.items():
        # print(user_credentials.values())
        # print(user_credentials.items())
        for username in user_credentials.keys():
            file.write(
                f"{username}:{user_credentials[username].get('password')}:{user_credentials[username].get('id_number')}:{user_credentials[username].get('userRole')}\n")


def serverListen(clientSocket):
    global userRole
    load_user_credentials()
    while True:
        print('server12')
        msg = clientSocket.recv(1024).decode("utf-8")
        print('server12222', msg)
        if msg == "/login":
            print('server122log')
            clientSocket.send(b"/login")
            username = clientSocket.recv(1024).decode("utf-8")
            clientSocket.send(b"/sendpassssssss")
            password = clientSocket.recv(1024).decode("utf-8")
            print(username, 'server122', password)
            if login_user(username, password):
                state["username"] = username
                clientSocket.send(b"/loginSuccess")
                clientSocket.recv(1024).decode("utf-8")
                clientSocket.send(user_credentials[username].get('id_number'))
                break
            else:
                clientSocket.send(b"/loginFailed")
        elif msg == "/register":
            print('server12reg', msg)
            clientSocket.send(b"/register")
            username = clientSocket.recv(1024).decode("utf-8")
            clientSocket.send(b"/sendpassssssss")
            password = clientSocket.recv(1024).decode("utf-8")
            print("\nsdata reseve =>  username:" + username + " password:" + password)
            clientSocket.send(b"/send id number")
            id_number = clientSocket.recv(1024).decode("utf-8")
            clientSocket.send(b"/send role")
            role = clientSocket.recv(1024).decode("utf-8")
            if role == "/addStudent":
                userRole = 1
            elif role == "/addProfessor":
                userRole = 0
            message = register_user(username, password, id_number, userRole)
            print("\nsnew user data : " + username, password, id_number)
            state["username"] = username
            clientSocket.send(bytes(message, "utf-8"))
        elif msg == "/add_info":
            print('add_info', msg)
            clientSocket.send(b"/add_info")
            key1 = bytes(user_credentials[state["username"]].get('id_number') + user_credentials[state["username"]].get(
                'id_number') + user_credentials[state["username"]].get('id_number') + user_credentials[
                             state["username"]].get('id_number') + user_credentials[state["username"]].get('id_number'),
                         "utf-8")  ##############
            key = key1[:16]
            ciphertext = clientSocket.recv(1024)
            clientSocket.send(b"/ciperreseve1")
            tag = clientSocket.recv(1024)
            clientSocket.send(b"/tagreseve1")
            nonce = clientSocket.recv(1024)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            print("\nsdata receve before decode:")
            print(ciphertext, tag)
            phone = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")  ####phone decode
            clientSocket.send(b"/sendemailll")
            ciphertext = clientSocket.recv(1024)
            clientSocket.send(b"/ciperreseve2")
            tag = clientSocket.recv(1024)
            clientSocket.send(b"/tagreseve2")
            nonce = clientSocket.recv(1024)
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            email = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8")  ####email decode
            print("your data after decode phone :" + phone + "email :" + email)
            user_info(phone, email)
            message = "your data added sussecfully  yourphone :" + phone + " youremail :" + email
            cipher = AES.new(key, AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext, tag = cipher.encrypt_and_digest(bytes(message, "utf-8"))
            print("data encode before send to client:")
            print(ciphertext, tag)
            clientSocket.send(ciphertext)
            clientSocket.recv(1024)
            clientSocket.send(tag)
            clientSocket.recv(1024)
            clientSocket.send(nonce)
        elif msg == "/manage_projects":
            print('server12pro', msg)
            clientSocket.send(b"/manage_projects")
            client_ip = str(clientSocket.getpeername()[0])
            print(session[client_ip])
            print(len(session[client_ip]))
            cipher_projects = clientSocket.recv(1024)
            clientSocket.send(b"/ciperreseve1")
            tag = clientSocket.recv(1024)
            clientSocket.send(b"/tagreseve1")
            nonce = clientSocket.recv(1024)
            cipher = AES.new(session[client_ip], AES.MODE_EAX, nonce=nonce)
            projects = cipher.decrypt_and_verify(cipher_projects, tag).decode("utf-8")  # Project decode
            user_projects(projects)
            print("enc res")
            cipher = AES.new(session[client_ip], AES.MODE_EAX)
            nonce = cipher.nonce
            ciphertext_message, tag = cipher.encrypt_and_digest(b"/done")  # message Encrept
            clientSocket.send(ciphertext_message)
            clientSocket.recv(1024)
            clientSocket.send(tag)
            clientSocket.recv(1024)
            clientSocket.send(nonce)
        elif msg == "/session":
            print("before rec")
            # Receive the encrypted session key from the client
            encrypted_session_key = clientSocket.recv(4096).decode("utf-8")
            encrypted_session_key = base64.b64decode(encrypted_session_key)
            # encrypted_session_key = msg
            print("before dec: ", private_key, "\n", encrypted_session_key)
            # Decrypt the session key using the server's private key
            session_key = pgpy_decrypt(private_key, encrypted_session_key)
            # print(len(session_key))
            # print(type(session_key))
            print("session is:  ", session_key)
            # Send confirmation to the client
            clientSocket.send(b"Session key received and agreed.")
            client_ip = str(clientSocket.getpeername()[0])
            session[client_ip] = session_key
            print(session)
        elif msg == "/add-students-menu":
            clientSocket.send(b"/add-students-menu")
            data_received = clientSocket.recv(4024)  # Adjust the buffer size as needed
            list_bytes, grades_bytes, signature_str = data_received.split(b'\n' , 2)
            list_str = list_bytes.decode('utf-8')
            grades_str = grades_bytes.decode('utf-8')
            # signature_str = signature_bytes.decode('utf-8')
            signature_bytes = base64.b64decode(signature_str)
            print("list_info:", list_str)
            print("Grades:", grades_str)
            print("Signature:", signature_str)
            # Convert the binary signature to the type expected by the verify method
            signature = pgpy.PGPSignature.from_blob(signature_bytes)
            print("Signature:", signature)
            # Assuming public_key is the public key corresponding to the private_key used for signing
            # Safely evaluate the string as a dictionary
            data_dict = ast.literal_eval(list_str)
            # Extract the first key
            first_key = list(data_dict.keys())[0]
            public_key = get_client_public_key(str(clientSocket.getpeername()[0])+first_key)
            is_verified = public_key.verify(grades_str.encode('utf-8'), signature)
            if is_verified:
                print("Signature verified successfully")
            else:
                print("Signature verification failed")
            
def user_info(phone, email):
    with open(USER_info_FILE, "a") as file:
        file.write(f"{state['username']}:{phone}:{email}\n")
        file.close()


def user_projects(projects):
    with open(USER_PROJECTS_FILE, "a") as file:
        file.write(f"{state['username']}:{projects}\n")
        file.close()


def register_user(username, password, id_number, userRole):
    if username not in user_credentials:
        user_credentials[username] = {'password': password, 'id_number': id_number, 'userRole': userRole}
        save_user_credentials()
        return "/registerSuccess"
    else:
        return "invalid username."


def login_user(username, password):
    return username in user_credentials and user_credentials[username].get('password') == password


# Function to add a client's public key
def add_client_public_key(client_identifier, public_key):
    client_public_keys[client_identifier] = public_key


# Function to get a client's public key
def get_client_public_key(client_identifier):
    return client_public_keys.get(client_identifier)


def main():
    if len(sys.argv) < 3:
        print("USAGE: python server.py <IP> <Port>")
        print("EXAMPLE: python server.py localhost 8000")
        return
    listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listenSocket.bind((sys.argv[1], int(sys.argv[2])))
    listenSocket.listen(10)
    print("PyconChat Server running")

    # Load or generate the private key 
    load_or_generate_private_key()
    print(private_key)
    global client_count

    while True:
        client, client_address = listenSocket.accept()
        threading.Thread(target=serverListen, args=(client,)).start()
        client_count += 1
        client.send(str(client_count).encode('utf-8'))
        # Receive client's public key --handshaking--
        client_public_key_bytes = client.recv(4096)
        client_public_key = pgpy.PGPKey()
        client_public_key.parse(client_public_key_bytes.decode('utf-8'))

        # Save client's public keys
        add_client_public_key(client_address[0]+str(client_count), client_public_key)
        print("Client's public key:", client_public_key)
        # print(client_public_keys)
        # Send server's public key to the client
        server_public_key_bytes = private_key.pubkey
        client.send(str(server_public_key_bytes).encode('utf-8'))
        # print("done")


if __name__ == "__main__":
    main()
