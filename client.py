import json
import socket
import threading
import pickle
import sys
import os
from io import BytesIO
from Crypto.Cipher import AES

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pgpy.constants import PubKeyAlgorithm, KeyFlags
from pgpy import PGPKey
from hyper import (Hyper , pgpy_decrypt , pgpy_encrypt)
import pgpy
import base64

state = {}
sission = {}
is_logged_in = False
private_key = None
server_public_key = None
global session_key

def serverListen(serverSocket):
	print('\nclient1')
	while True:
		msg = serverSocket.recv(1024).decode("utf-8")
		print("---aaaaaaa", msg)
		if msg == "/login":
			print('\nclient1log')
			print("Please Enter your username:")
			with state["inputCondition"]:
				state["inputCondition"].wait()
			state["inputMessage"] = True
			serverSocket.send(bytes(state["userInput"],"utf-8"))   #username send
			password = input("Choose a password: ")
			serverSocket.recv(1024)
			serverSocket.send(bytes(password, "utf-8"))     #password send
			response = serverSocket.recv(1024).decode("utf-8")
			print(response)
			if response == "/loginSuccess":
				serverSocket.send(b"/get_id_number")
				state["id_number"]=serverSocket.recv(1024)
				state["alive"] = True
				is_logged_in = True
				print("Login successful!")
				break
			else:
				print("Login failed. Please try again.")
		elif msg == "/register":
			print('\nclient12reg')  
			state["inputMessage"] = False
			print("Please enter the usernamerrrrrrrrrrr ")
			with state["inputCondition"]:
				state["inputCondition"].wait()
			state["inputMessage"] = True
			serverSocket.send(bytes(state["userInput"],"utf-8"))   #username send
			print('\nclient1reggggggg')
			password = input("Choose a password: ")
			serverSocket.recv(1024)
			serverSocket.send(bytes(password, "utf-8"))
			id_number = input("Please enter your id_number:")
			serverSocket.recv(1024)
			serverSocket.send(bytes(id_number, "utf-8"))      #id_number send
			response = serverSocket.recv(1024).decode("utf-8")
			print(response)
			if response == "/registerSuccess":
				state["id_number"]=id_number
				state["alive"] = True
				is_logged_in = True
				print("Registration successful! You can now login.")
				print("Available Commands:\n/1 -> Add extra information\n/2 -> Enter your projects\n")
				choose = input("choose: ")
				if choose =="/1":
					serverSocket.send(b"/add_info")
				elif choose =="/2":
					serverSocket.send(b"/manage_projects")
			else:
				print("Registration failed. Username may already be taken.")
				##
		elif msg == "/add_info":
			print('\nclientadd_info')  
			state["inputMessage"] = False
			phone = input("enter phone number: ")
			key1 =bytes(state["id_number"]+state["id_number"]+state["id_number"]+state["id_number"]+state["id_number"], "utf-8")    ###key  gene 
			key=key1[:16]
			cipher = AES.new(key, AES.MODE_EAX)
			ciphertext, tag = cipher.encrypt_and_digest(bytes(phone,"utf-8"))    ##phone encode
			print("phone  encode before send :")
			print(ciphertext+tag)
			nonce=cipher.nonce
			serverSocket.send(ciphertext)     
			serverSocket.recv(1024)
			serverSocket.send(tag)   
			serverSocket.recv(1024)
			serverSocket.send(nonce)   
			serverSocket.recv(1024)
			email = input("Choose a email: ")
			cipher = AES.new(key, AES.MODE_EAX)
			nonce=cipher.nonce
			ciphertext2, tag2 = cipher.encrypt_and_digest(bytes(email,"utf-8"))       ##email encode
			print(ciphertext2+tag2)
			serverSocket.send(ciphertext2)     
			serverSocket.recv(1024)
			serverSocket.send(tag2)   
			serverSocket.recv(1024)
			serverSocket.send(nonce)   
			print('\nserver responce is :')  
			ciphertext=serverSocket.recv(1024)
			serverSocket.send(b"/ciperreseve2")   
			tag=serverSocket.recv(1024)
			serverSocket.send(b"/tagreseve2")   
			nonce=serverSocket.recv(1024)
			cipher = AES.new(key, AES.MODE_EAX,nonce=nonce)
			server_response = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8") 
			print(server_response)
			break
		elif msg == "/manage_projects":
			print("\n" , session_key)
			print(len(session_key))
			print("\n client projects:")
			projects = input("Enter your list of projects (comma-separated): ")
			cipher = AES.new(session_key, AES.MODE_EAX)
			ciphertext, tag = cipher.encrypt_and_digest(bytes(projects, "utf-8"))    # Projects encode
			print("projects encode before send :")
			nonce = cipher.nonce
			serverSocket.send(ciphertext)
			serverSocket.recv(1024)
			serverSocket.send(tag)   
			serverSocket.recv(1024)
			serverSocket.send(nonce)   
			response = serverSocket.recv(1024) # recive response
			serverSocket.send(b"/ciperreseve2")   
			tag = serverSocket.recv(1024)
			serverSocket.send(b"/tagreseve2")   
			nonce = serverSocket.recv(1024)
			cipher = AES.new(session_key, AES.MODE_EAX , nonce = nonce)
			response = cipher.decrypt_and_verify(response, tag).decode("utf-8") 
			print(response)
			if response == "/done":
				print("your projects stored.")
			else:
				print("something wrong!")
		else:
			print(msg)

def userInput(serverSocket):
	while True:
		state["sendMessageLock"].acquire()
		state["userInput"] = input()
		state["sendMessageLock"].release()
		with state["inputCondition"]:
			state["inputCondition"].notify()
		if state["userInput"] == "/1":
			serverSocket.send(b"/login")
		elif state["userInput"] == "/2":
			serverSocket.send(b"/register")
		# elif state["userInput"] == "/3" and is_logged_in:
		# 	serverSocket.send(b"/manage_projects")
			# projects = input("Enter your list of projects (comma-separated): ")
			# serverSocket.send(bytes(projects, "utf-8"))
			# print("Projects sent successfully!")
		else:
			# print("Invalid choice.")
			with state["inputCondition"]:
				state["inputCondition"].wait()
		# if state["userInput"] == "/1" or state["userInput"] == "/2":
		# 	serverSocket.send(state["userInput"].encode("utf-8"))			

def main():
	if len(sys.argv) < 3:
		print("USAGE: python client.py <IP> <Port>")
		print("EXAMPLE: python client.py localhost 8000")
		return
	serverSocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	serverSocket.connect((sys.argv[1], int(sys.argv[2])))
	state["inputCondition"] = threading.Condition()
	state["sendMessageLock"] = threading.Lock()
	state["alive"] = False     

	hyper = Hyper()

	try:
		# Load private key
		with open("client_private_key.asc", "r") as f:
			private_key, _ = pgpy.PGPKey.from_file(f)
	except Exception as e:
		print(f"Error loading private key: {e}")
		private_key = hyper.pgp('client_')

	# print(private_key)
	# Send client's public key to the server
	client_public_key_bytes = private_key.pubkey
	serverSocket.send(str(client_public_key_bytes).encode('utf-8'))

	# Receive server's public key
	server_public_key_bytes = serverSocket.recv(4096)

	server_public_key = pgpy.PGPKey()
	server_public_key.parse(server_public_key_bytes.decode('utf-8'))
	print("Server's public key:", server_public_key)

	# Generate a random session key
	global session_key
	session_key = os.urandom(16)  # 128-bit key
	print(session_key)
	# Encrypt the session key using the server's public key
	encrypted_session_key = pgpy_encrypt(server_public_key , session_key)
	print("before send")
	# Send the encrypted session key to the server
	serverSocket.send(b"/session")
	# serverSocket.send(bytes(str(encrypted_session_key).encode('utf-8')))
	encoded_session_key = base64.b64encode(encrypted_session_key).decode("utf-8")
	serverSocket.send(encoded_session_key.encode("utf-8"))

	# Receive the server's confirmation
	confirmation = serverSocket.recv(1024).decode("utf-8")
	print("Server's confirmation:", confirmation)

	print("Welcome to uniSite!\nAvailable Commands:\n/1 -> Login\n/2 -> Signin")
	print("Enter your choice: ")

	serverListenThread = threading.Thread(target=serverListen, args=(serverSocket,))
	userInputThread = threading.Thread(target=userInput, args=(serverSocket,))

	serverListenThread.start()
	userInputThread.start()

	serverListenThread.join()
	userInputThread.join()
	
	while True:
		if not state["alive"]:
			serverSocket.shutdown(socket.SHUT_RDWR)
			serverSocket.close()
			print("Disconnected from PyconChat.")
			break
		

if __name__ == "__main__":
	main()