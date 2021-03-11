import socket
import sys
from _thread import *

global usernum			#The total num of the client
usernum =0
global usertype			# 2 more = users 0,1 = user
usertype = 'user'
global client_list		# client list 
client_list =[]
global addbool			#if new client get in
addbool = 0

#declare of global variable

def threaded(client_socket, addr): 
	global usernum
	if usernum >1:
		usertype = 'users'
	else:
		usertype = 'user'

	client_socket.send(str(usernum).encode())

	newinfo = "New user "+addr[0]+":"+str(addr[1])+" entered"+" ("+str(usernum)+" "+usertype+" online)"
	if addbool ==1:
		for i in range(len(client_list)-1):
			client_list[i].send(newinfo.encode()) 
	print(newinfo)

 
    # untill the client end 
	while True: 

		try:
            # when the data get in send to client again
			data = client_socket.recv(1024)

			if not data:
				usernum -=1
				if usernum >1:
					usertype = 'users'
				else:
					usertype = 'user'
				exitsrt = "The user "+addr[0]+":"+str(addr[1])+" left"+" ("+str(usernum)+" "+usertype+" online)"
				print(exitsrt)
				client_list.remove(client_socket)
				for i in range(len(client_list)):
					client_list[i].send(exitsrt.encode()) 

				break
			#when the client leaving

			print('[' + addr[0],end='')
			print(':',end='')
			print(addr[1],end ='')
			print(']', data.decode())

			for i in range(len(client_list)):
				if client_list[i] == client_socket:
					you = "[You] "
					client_list[i].send(you.encode()) 
				else:
					ipad = "["+addr[0]+":"+str(addr[1])+"] "
					client_list[i].send(ipad.encode())
			
			for i in range(len(client_list)):
				client_list[i].send(data) 

			#for receive the data and sending to all client
		except ConnectionResetError as e:
			usernum -=1
			if usernum >1:
				usertype = 'users'
			else:
				usertype = 'user'
			exitsrt = "The user "+addr[0]+":"+str(addr[1])+" left"+" ("+str(usernum)+" "+usertype+" online)"
			print(exitsrt)
			client_list.remove(client_socket)
			break
		#when the client occur the error 
             
	client_socket.close() 

#start of the main

HOST = sys.argv[1]
PORT = sys.argv[2]
print("Chat Server started on port " + PORT + ".")
#get the input for ip and port

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind((HOST, int(PORT))) 
server_socket.listen() 
#setting the server option and function


while True: 

# when the client comes accept will return new socket and will communicate with socket in new thread  
	try:
		client_socket, addr = server_socket.accept()
		usernum +=1
		addbool = 1
		client_list.append(client_socket)			# add the client list
		start_new_thread(threaded, (client_socket, addr)) 

#when the Keyboardinterrupt occuer
	except KeyboardInterrupt:	
		server_socket.close()
		print("")
		print('exit')
		break

server_socket.close() 
