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
DC_requests_FILE = "DC_requests.txt"
USER_PROJECTS_FILE = "user_projects.txt"
USER_MARKS_FILE = "user_marks.txt"
user_credentials = {}
DC_requests = {}
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

def load_DC_requests():
    if os.path.exists(DC_requests_FILE):
        with open(DC_requests_FILE, "r") as file:
            #lines = file.readlines()
            #for line in lines:
            #username, user_pupk,mathm,solv = line.strip().split(":")
            lines = file.read()
            #username, user_pupk,mathm,solv = lines.strip().split(":")
            xx = lines.split(",,")
            print(xx)
            for one in xx:
                if one =="\n":
                    print("bbbbbbbbbbbbb")
                    break
                else:
                    print(one)
                    print("rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr")
                    username, user_pupk,mathm,solv = one.split(":")
                    DC_requests[username] = {'user_pupk': user_pupk, 'mathm': mathm, 'solv': solv}

def save_DC_requests():
    with open(DC_requests_FILE, "w") as file:
        for username in DC_requests.keys():
            file.write(
                f"{username}:{DC_requests[username].get('user_pupk')}:{DC_requests[username].get('mathm')}:{DC_requests[username].get('solv')},,\n")


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
        for username in user_credentials.keys():
            file.write(
                f"{username}:{user_credentials[username].get('password')}:{user_credentials[username].get('id_number')}:{user_credentials[username].get('userRole')},,\n")

def save_user_marks(client_ip, data):
    with open(USER_MARKS_FILE, "w") as file:
            file.write(
                f"{client_ip}:{data}")
            
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
                clientSocket.send(bytes(str(user_credentials[username].get('id_number')) , 'utf-8'))
                clientSocket.recv(1024).decode("utf-8")
                clientSocket.send(bytes(str(user_credentials[username].get('userRole')) , 'utf-8'))
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
            client_info = clientSocket.recv(1024).decode("utf-8")
            clientSocket.send(b"\done")
            client_ip = str(clientSocket.getpeername()[0]+client_info)
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
            client_info = clientSocket.recv(1024).decode("utf-8")
            clientSocket.send(b"\done")
            # print("after:" , client_info)
            # Receive the encrypted session key from the client
            encrypted_session_key = clientSocket.recv(4096).decode("utf-8")
            encrypted_session_key = base64.b64decode(encrypted_session_key)
            # encrypted_session_key = msg
            print("before dec: ", private_key, "\n", encrypted_session_key)
            # Decrypt the session key using the server's private key
            session_key = pgpy_decrypt(private_key, encrypted_session_key)
            print("session is:  ", session_key)
            # Send confirmation to the client
            clientSocket.send(b"Session key received and agreed.")
            client_ip = str(clientSocket.getpeername()[0]+client_info)
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
                save_user_marks(list_str , grades_str)
                print("Signature verified successfully")
                clientSocket.send(b"\done")
            else:
                print("Signature verification failed")
        elif msg == "/request_get_DC":
            print('server12DC', msg)
            load_DC_requests()
            clientSocket.send(b"/request_get_DC")
            username = clientSocket.recv(1024).decode("utf-8")
            clientSocket.send(b"/sendkeyyyy")
            user_pupk = clientSocket.recv(1024).decode("utf-8")
            message = DC_request(username,user_pupk)    
            clientSocket.send(bytes(message, "utf-8"))
        elif msg == "/show_request_DC":
            load_DC_requests()
            print('server12S_DC', msg)
            clientSocket.send(b"/show_request_DC")
            clientSocket.recv(1024)
            req=str(DC_requests)
            clientSocket.send(str(req).encode('utf-8'))
            #clientSocket.send(bytes(req, "utf-8"))
            respo=clientSocket.recv(1024).decode("utf-8")
            if respo=="/0":
                break
            clientSocket.send(b"/username_re recive")
            mathm1=clientSocket.recv(1024).decode("utf-8")
            clientSocket.send(b"/mathm1 recive")
            solv1=clientSocket.recv(1024).decode("utf-8")
            pupk=DC_requests[respo].get('user_pupk')
            print(mathm1)
            DC_requests[respo]={'user_pupk': pupk,"mathm":mathm1,"solv":solv1}
            save_DC_requests()


        else:
            clientSocket.send(b"\none")

def user_info(phone, email):
    with open(USER_info_FILE, "a") as file:
        file.write(f"{state['username']}:{phone}:{email}\n")
        file.close()

def DC_request(username,user_pupk):
    if username not in DC_requests:
        DC_requests[username] = {'user_pupk': user_pupk,"mathm":None,"solv":None}
        save_DC_requests()
        return "\nyour request send to CA successfuly "
    else:
        return "you have send a request before."

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
    print("UniSite Server running")

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
