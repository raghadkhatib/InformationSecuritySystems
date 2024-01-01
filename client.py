import json
import socket
import threading
import pickle
import sys
import os
from io import BytesIO
from Crypto.Cipher import AES
from datetime import datetime

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
grades = {}
client_info = {}
global is_logged_in
is_logged_in = False
global private_key
private_key = None
server_public_key = None
global session_key
global client_list
client_list = 0
global client_ip
client_ip = None

def command(serverSocket):
	print("logg:   ",is_logged_in)
	if is_logged_in:
		print("Available Commands:\n/1 -> Add extra information\n/6 -> Logout\n")
		if state["userRole"] == 1:
			print("/2 -> Enter your projects\n")
		if state["userRole"] == 0:
			print("/3 -> Enter Student Marks\n")
		if state["userRole"] == 0:
			print("/4 -> send request to get DC \n")
		if state["userRole"] == 2:
			print("/5 -> show request to get DC \n")
		choose = input("choose: ")
		if choose =="/1":
			serverSocket.send(b"/add_info")
		elif choose =="/2":
			serverSocket.send(b"/manage_projects")
		elif choose =="/3":
			serverSocket.send(b"/add-students-menu")
		elif choose =="/4":
			serverSocket.send(b"/request_get_DC")
		elif choose =="/5":
			serverSocket.send(b"/show_request_DC")
		elif choose == "/6":
			serverSocket.shutdown(socket.SHUT_RDWR)
			serverSocket.close()
			print("Disconnected from UniSite.")
		else:
			command(serverSocket)

def serverListen(serverSocket):
	# print('\nclient1')
	while True:
		msg = serverSocket.recv(1024).decode("utf-8")
		print("---", msg)
		if msg == "/login":
			# print('\nclient1log')
			print("Please Enter your username:")
			with state["inputCondition"]:
				state["inputCondition"].wait()
			state["inputMessage"] = True
			state["username"]=state["userInput"]
			serverSocket.send(bytes(state["username"],"utf-8"))   #username send
			password = input("Choose a password: ")
			serverSocket.recv(1024)
			serverSocket.send(bytes(password, "utf-8"))     #password send
			response = serverSocket.recv(1024).decode("utf-8")
			print(response)
			global is_logged_in
			if response == "/loginSuccess":
				serverSocket.send(b"/get_id_number")
				state["id_number"]=serverSocket.recv(1024).decode('utf-8')
				serverSocket.send(b"/get_role")
				state["userRole"]=int(serverSocket.recv(1024).decode('utf-8'))
				state["alive"] = True
				is_logged_in = True
				print("Login successful!")
				command(serverSocket)
			else:
				print("Login failed. Please try again.")
		elif msg == "/register":
			# print('\nclient12reg')  
			state["inputMessage"] = False
			print("Please enter the username:  ")
			with state["inputCondition"]:
				state["inputCondition"].wait()
			state["inputMessage"] = True
			state["username"]=state["userInput"]
			serverSocket.send(bytes(state["userInput"],"utf-8"))   #username send
			# print('\nclient1reggggggg')
			password = input("Enter a password: ")
			serverSocket.recv(1024)
			serverSocket.send(bytes(password, "utf-8"))
			id_number = input("Please enter your national_number:")
			serverSocket.recv(1024)
			serverSocket.send(bytes(id_number, "utf-8"))
			role = input("Please enter your role: 1- Student, 2- Professor\n")
			serverSocket.recv(1024)
			if role == "1":
				state["userRole"] = 1
				serverSocket.send(b"/addStudent")
			elif role == "2":
				state["userRole"] = 0
				serverSocket.send(b"/addProfessor")
			response = serverSocket.recv(1024).decode("utf-8")
			print(response)
			if response == "/registerSuccess":
				state["id_number"]=id_number
				state["alive"] = True
				is_logged_in = True
				print("Registration successful! You can now login.")
				command(serverSocket)
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
			email = input("Enter an email: ")
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
			command(serverSocket)
		elif msg == "/manage_projects":
			print("\n" , session_key)
			print(len(session_key))
			serverSocket.send(bytes(client_ip , "utf-8"))
			serverSocket.recv(1024)
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
			# print(response)
			if response == "/done":
				print("your projects stored.")
			else:
				print("something wrong!")
			command(serverSocket)
		elif msg == "/add-students-menu":
			global client_list
			client_list += 1
			subject_name = input("Enter subject's name: ")
			grades["subject_name"] = subject_name
			while True:
				student_name = input("Enter student's name (or '/' to finish): ")
				if student_name == '/':
					break
				grade = input(f"Enter grade for {student_name}: ")
				grades[student_name] = grade
			timestamp = datetime.utcnow()
			grades["time"] = timestamp
			grades_str = str(grades)
			client_info[client_ip] = client_list
			print("this ------", timestamp)
			signature = private_key.sign(grades_str.encode('utf-8'), timestamp=timestamp)
			client_bytes = bytes(str(client_info), 'utf-8')
			grades_bytes = bytes(grades_str, 'utf-8')
			# signature_bytes = bytes(str(signature), 'utf-8')
			signature_bytes = bytes(signature)
			signature_str = base64.b64encode(signature_bytes).decode('utf-8')
			data_to_send = client_bytes + b'\n' + grades_bytes + b'\n' +  signature_str.encode('utf-8')
			serverSocket.send(data_to_send)
			# print("Grades:", grades_str)
			# print("Signature:", signature)
			response = serverSocket.recv(1024).decode("utf-8")
			if response == "/done":
				print("your projects stored.")
			else:
				print("something wrong!")
			command(serverSocket)
		elif msg == "/request_get_DC":
			print('\nclient_request_get_DC')  
			serverSocket.send(bytes(state["username"],"utf-8"))    
			serverSocket.recv(1024)
			serverSocket.send(str(state["pup_k"]).encode('utf-8'))
			#serverSocket.send(bytes(state["pup_k"],"utf-8"))
			massege=serverSocket.recv(1024)
			print(massege)
			break
		elif msg == "/show_request_DC":
			print('\nclientCA_show_request_DC')  
			serverSocket.send(b"/WAITING THE REQUESTS")  
			requests=serverSocket.recv(1024)
			for username in requests.keys():
				print(f"{username}:{requests[username].get('user_pupk')}:{requests[username].get('mathm')}:{requests[username].get('solv')}\n")
			username_re=input("enter username you want to send varify  or enter /0 to break")
			serverSocket.send(username_re)
			if username_re=="/0":
				break
			else:
				mathm=serverSocket.recv(1024) 
				mathm=input("enter the moadala you want proff to solve :")
				serverSocket.send(bytes(mathm, "utf-8"))
				serverSocket.recv(1024)
				solv=input("enter the correct solve  :") 
				serverSocket.send(bytes(solv, "utf-8")) 
			break
		else:
			command(serverSocket)

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
	global private_key
	global client_ip
	client_ip = serverSocket.recv(1024).decode("utf-8")
	print(client_ip)

	try:
		# Load private key
		with open("client_"+client_ip+"private_key.asc", "r") as f:
			private_key, _ = pgpy.PGPKey.from_file(f)
	except Exception as e:
		print(f"Error loading private key: {e}")
		private_key = hyper.pgp('client_' + client_ip)

	# print(private_key)
	# Send client's public key to the server
	client_public_key_bytes = private_key.pubkey
	serverSocket.send(str(client_public_key_bytes).encode('utf-8'))
	state["pup_k"]=client_public_key_bytes
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
	serverSocket.send(bytes(client_ip , "utf-8"))
	serverSocket.recv(1024)
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
			print("Disconnected from UniSite.")
			break
		

if __name__ == "__main__":
	main()