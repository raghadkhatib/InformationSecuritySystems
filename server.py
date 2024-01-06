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
certificats_FILE = "certificats.txt"
USER_PROJECTS_FILE = "user_projects.txt"
USER_MARKS_FILE = "user_marks.txt"
user_credentials = {}
DC_requests = {}
certificats = {}
state = {}
session = {}
global private_key
private_key = None
client_public_keys = {}
global client_count
client_count = 0
mark={}

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
            lines = file.read()
            xx = lines.split(",,")
            print(xx)
            for one in xx:
                if one =="\n" or one=='':
                    break
                else:
                    print(one)
                    username, user_pupk,mathm,solv,ver = one.split(":")
                    DC_requests[username] = {'user_pupk': user_pupk, 'mathm': mathm, 'solv': solv, 'verify': ver}

def load_certificats_FILE():                    
    if os.path.exists(certificats_FILE):
        with open(certificats_FILE, "r") as file:
            lines = file.read()
            xx = lines.split(",,")
            print(xx)
            for one in xx:
                if one =="\n" or one=='':
                    print("bbbbbbbbbbbbb")
                    break
                else:
                    print(one)
                    print("rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr")
                    username, cert,cert_data,CA_pup = one.split("::")
                    certificats[username] = {'cert': cert,'cert_data':cert_data, 'CA_pup': CA_pup}

def save_certificats():          ############not use yet
    with open(certificats_FILE, "w") as file:
        for username in certificats.keys():
            file.write(
                f"{username}:{certificats[username].get('cert')}:{certificats[username].get('cert_data')}:{certificats[username].get('CA_pup')},,")

def save_DC_requests():
    with open(DC_requests_FILE, "w") as file:
        for username in DC_requests.keys():
            file.write(
                f"{username}:{DC_requests[username].get('user_pupk')}:{DC_requests[username].get('mathm')}:{DC_requests[username].get('solv')}:{DC_requests[username].get('verify')},,")


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
                f"{username}:{user_credentials[username].get('password')}:{user_credentials[username].get('id_number')}:{user_credentials[username].get('userRole')}\n")

def load_user_marks_file():                    
    if os.path.exists(USER_MARKS_FILE):
        with open(USER_MARKS_FILE, "r") as file:
            xx = file.readlines()
            i=0
            for one in xx:
                i+=1
                client_ip, data,nn= one.split("::")
                mark[i] = data
                print(mark[i])

def save_user_marks(client_ip, data):
    with open(USER_MARKS_FILE, "a") as file:     # a 
            file.write(
                f"{client_ip}::{data}::\n")
            
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
        elif msg == "/request_get_DC":                 ## add & save proff csr to DC_requestS
            print('server12DC', msg)
            load_DC_requests()
            clientSocket.send(b"/request_get_DC")
            username = clientSocket.recv(1024).decode("utf-8")
            clientSocket.send(b"/sendkeyyyy")
            user_pupk = clientSocket.recv(4096).decode("utf-8")
            message = DC_request(username,user_pupk)    
            clientSocket.send(bytes(message, "utf-8"))
        elif msg == "/my_request_state":                     ## send csr state to proff and verify
            print('server12', msg)
            load_DC_requests()
            clientSocket.send(b"/my_request_state")
            name = clientSocket.recv(1024).decode("utf-8")
            quest=DC_requests[name].get('mathm')     
            print(quest)
            if quest==None:
                clientSocket.send(bytes("/waiting", "utf-8"))
            else:
                clientSocket.send(bytes(quest, "utf-8"))
                answe=clientSocket.recv(1024).decode("utf-8")
                if answe==DC_requests[name].get('solv'):
                    clientSocket.send(b"/verify done CA will give uou certifcat ")
                    pupk=DC_requests[name].get('user_pupk')
                    DC_requests.update({name:{'user_pupk': pupk,'mathm':quest,'solv':answe,'verify':"yes"}})
                    save_DC_requests()
                    ###########give dc
                else:
                    clientSocket.send(b"/verify failed try again")
                
        elif msg == "/show_request_DC":       ##send csr to CA 
            load_DC_requests()
            print('server12S_DC', msg)
            clientSocket.send(b"/show_request_DC")
            clientSocket.recv(1024)
            req=str(DC_requests)
            clientSocket.send(str(req).encode('utf-8'))
            respo=clientSocket.recv(1024).decode("utf-8")
            if respo=="/0":
                break
            clientSocket.send(b"/username_re recive")
            mathm1=clientSocket.recv(1024).decode("utf-8")
            clientSocket.send(b"/mathm1 recive")
            solv1=clientSocket.recv(1024).decode("utf-8")
            pupk=DC_requests[respo].get('user_pupk')
            print(mathm1)
            DC_requests.update({respo:{'user_pupk': pupk,'mathm':mathm1,'solv':solv1,'verify':None}})
            save_DC_requests()
        elif msg == "/give_certificat":                 ## add & save proff csr to DC_requestS
            print('server12DC', msg)
            load_DC_requests()
            clientSocket.send(b"/give_certificat")
            clientSocket.recv(1024)
            req=str(DC_requests)
            clientSocket.send(str(req).encode('utf-8'))
            usname=clientSocket.recv(1024).decode("utf-8")
            pupk=DC_requests[usname].get('user_pupk')
            clientSocket.send(bytes(pupk, "utf-8"))
            cert=clientSocket.recv(8600).decode("utf-8")
            clientSocket.send(b"send ca pupk")
            ca_pup=clientSocket.recv(4096).decode("utf-8")  ##
            clientSocket.send(b"send cert data bytes")
            cert_data=clientSocket.recv(8600).decode("utf-8")
            print(cert_data)
            add_certificat(usname,cert,cert_data,ca_pup)
        elif msg == "/get_mark":
            clientSocket.send(b"/get_mark")
            load_certificats_FILE()
            usernam = clientSocket.recv(4024).decode("utf-8")
            clientSocket.send(b"send cert")
            certif = clientSocket.recv(4024).decode("utf-8")  
            cert=certificats[usernam].get('cert')
            if certif!=cert:
                mass="error certificat wrong"
                clientSocket.send(str(mass).encode('utf-8'))
                break
            else:
                mass="cheking certificat now"
                clientSocket.send(str(mass).encode('utf-8'))
            clientSocket.recv(4096)
            cert_data_str = str(certificats[usernam].get('cert_data'))
            signature = pgpy.PGPSignature.from_blob(cert)
            print("Signature:", signature)
            ca_pupkey=certificats[usernam].get('CA_pup')
            keyy=bytes(ca_pupkey,"utf-8")
            blic_key = pgpy.PGPKey()
            blic_key.parse(keyy.decode('utf-8'))
            print(ca_pupkey)
            is_verified = blic_key.verify(cert_data_str, signature)
            ##
            if is_verified:
                print("certificat Signature verified successfully")
                clientSocket.send(b"\certificat Signature verified successfully")
                clientSocket.recv(1024)
                load_user_marks_file()
                certdata={}
                certdata=ast.literal_eval(certificats[usernam].get('cert_data'))
                print(certdata)
                authn=certdata[usernam].get('auth')
                if authn=='/0':
                    clientSocket.send(b"you have authantcat to see all mark")
                    clientSocket.recv(1024)
                    clientSocket.send(str(mark).encode('utf-8'))
                else:
                    clientSocket.send(b"you have authantcat to see only one subject mark")
                    clientSocket.recv(1024)
                    marksen={}
                    #data_str = str(mark)
                    #markkk=ast.literal_eval(data_str)
                    for list in mark.keys():
                        #sss=mark[list]
                        print(mark[list])
                        #markkk={}
                        markkk=ast.literal_eval(str(mark[list]))
                        if markkk['subject_name']==authn:
                            marksen[list]=mark[list]
                    clientSocket.send(str(marksen).encode('utf-8'))
            else:
                print("certificat verification failed")
                clientSocket.send(b"\certificat verification failed")

        else:
            clientSocket.send(b"\none")

def user_info(phone, email):
    with open(USER_info_FILE, "a") as file:
        file.write(f"{state['username']}:{phone}:{email}\n")
        file.close()

def DC_request(username,user_pupk):
    if username not in DC_requests:
        DC_requests[username] = {'user_pupk': user_pupk,'mathm':None,'solv':None,'verify':None}
        save_DC_requests()
        return "\nyour request send to CA successfuly "
    else:
        return "you have send a request before."
    
def add_certificat(usname,cert,cert_data,ca_pup):
    with open(certificats_FILE, "a") as file:
        file.write(f"{usname}::{cert}::{cert_data}::{ca_pup},,")
        #file.close()

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
