import socket
import sys
import threading

global word_list
word_list =[]
global booling
booling = 1

#declartion of global variation

def received(client_socket):
	while True:
		data = client_socket.recv(1024)
		print(data.decode())

# when the data received

def sended(client_socket): 
	while True:

		message = input('')
		client_socket.send(message.encode())

# when send the data

# start of main
user_type = 'user'
HOST = sys.argv[1]
PORT = sys.argv[2]
# get the info of input

client_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
client_socket.connect((HOST, int(PORT)))
data = client_socket.recv(1024)
# connet with the server

server_num = int(data.decode())
if server_num >1: 
	user_type = 'users'
else:
	user_type = 'user'
print('Connected to the chat server (',end='')
print(server_num,user_type,'online)')
# check the number of user and print the info

while True: 
	try:
		th_a = threading.Thread(target=received,args=(client_socket,))
		th_b = threading.Thread(target=sended,args=(client_socket,))
		th_a.daemon= True
		th_b.daemon= True
		th_a.start()
		th_b.start()
		th_a.join()
		th_b.join()
# make 2 thread (received and sended), start and use join for wait
	except KeyboardInterrupt:
		client_socket.close()
		print("")
		print('exit')
		break
# if KeyboardInterrupt occur finish the whole 
client_socket.close()
