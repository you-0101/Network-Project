import socket
import sys
import threading
import requests

global threadid
threadid =[0 for i in range(100)]
global count
count =0
global boolredi
boolredi =0
global boolimage
boolimage =0

def prx_cli(data):									#proxy server's response info
	try:
		index =data.find(b'\r\n\r\n')
		cli_to_prx = data[:index].decode()
		index = cli_to_prx.find('\r\n')
		first_line = cli_to_prx[:index]					# check the http signal success or not
		if (cli_to_prx.find('Content-Type')==-1):		# check the content type
			second_line = 'Not specified'				

		else:
			index = cli_to_prx.find('Content-Type:')
			if(cli_to_prx[index+14:].find('\r\n')==-1):
				second_line = cli_to_prx[index+14:]
			else:

				index2=cli_to_prx[index+14:].find('\r\n')
				second_line = cli_to_prx[index+14:index+index2+14]

		return 	first_line,second_line					#return the http info and content type
	except:
		first_line ='ERROR'
		second_line ='ERROR'
		return  first_line,second_line

def prx_serv(data):										#check the header and get the info of URL,HOST,AGENT
	global boolimage
	try:
		index =data.find(b'\r\n\r\n')
		cli_to_prx = data[:index].decode()
		if(cli_to_prx.find('GET') != -1):				#If header contain the 'GET'
			
			index=cli_to_prx.find('GET')
			index2=cli_to_prx.find('\n')
			first_line = cli_to_prx[index:index2-1]
			cli_to_prx =cli_to_prx[index2+1:]

			url = first_line[:-9]									#Checking the if image filtering off or on
			if(url[-10]=='?' and url[-9:].find('image_off')!=-1):
				boolimage =1
			if(url[-9]=='?' and url[-8:].find('image_on')!=-1):
				boolimage =0

			index=cli_to_prx.find('Host:')
			index2=cli_to_prx.find('\n')
			second_line = cli_to_prx[index+6:index2-1]
			cli_to_prx =cli_to_prx[index2+1:]


			index=cli_to_prx.find('Agent:')
			index2=cli_to_prx.find('\n')
			third_line = cli_to_prx[index+7:index2-1]
			cli_to_prx =cli_to_prx[index2+1:]

			return 	first_line,second_line,third_line
		
		else:											#If header not contain the 'GET' 
			first_line ='-1'

			index=cli_to_prx.find('Host:')
			cli_to_prx =cli_to_prx[index:]
			index2=cli_to_prx.find('\n')
			second_line = cli_to_prx[index+6:index2-1]

			third_line ='-1'

			return 	first_line,second_line,third_line		# -> just get the HOST, other URL,AGENT is -1
	except:													#when error occur
			first_line ='-1'
			second_line ='-1'
			third_line ='-1'
			return 	first_line,second_line,third_line		# error-> all HOST,URL,AGENT is -1

def image_filter(data):									#when the image filtering is happen
	try:
		index =data.find(b'\r\n\r\n')
		cli_to_prx = data[:index].decode()
		if (cli_to_prx.find('image')==-1):					#check the image or not (this case is not image)
			first_line = cli_to_prx[:index]
			if (cli_to_prx.find('Content-Type')==-1):
				second_line = 'Not specified'

			else:
				index = cli_to_prx.find('Content-Type:')
				if(cli_to_prx[index+14:].find('\r\n')==-1):
					second_line = cli_to_prx[index+14:]
				else:
					index2=cli_to_prx[index+14:].find('\r\n')
					second_line = cli_to_prx[index+14:index+index2+14]
			signal =0											# it mean this header not contain image
			return first_line,second_line,data,signal			#when it is not image check the http and content type and return with signal
		else:													#when it contain the image
			first_line = cli_to_prx[:index]
			if (cli_to_prx.find('Content-Type')==-1):
				second_line = 'Not specified'

			else:
				index = cli_to_prx.find('Content-Type:')
				if(cli_to_prx[index+14:].find('\r\n')==-1):
					second_line = cli_to_prx[index+14:]
				else:
					index2=cli_to_prx[index+14:].find('\r\n')
					second_line = cli_to_prx[index+14:index+index2+14]
			data = cli_to_prx.encode()
			signal =1										# it mean this header contain image
			return first_line,second_line,data,signal			#when it is image check the http and content type and return with signal
	except:
		first_line ='ERROR'
		second_line ='ERROR'
		signal =0
		return first_line,second_line,data,signal

def redirection(data,first,second):							# Check the 'yonsei' and do redirection and change the 'connection' to close
	global boolredi
	cli_to_prx =data.decode()
		
	if (second.find('yonsei') ==-1):						# Not yonsei -> just change the connection
		index=cli_to_prx.find('GET')
		index2=cli_to_prx.find('\n')
		index=cli_to_prx.find('GET')
		index2=cli_to_prx.find('\n')
		indextmp = index2
		index=cli_to_prx[index2+1:].find('Host:')+indextmp
		index2=cli_to_prx[index2+1:].find('\n')+indextmp
		index=cli_to_prx.find('Host:')
		index2=cli_to_prx[index:].find('\n')+indextmp+1	
		indextmp = index2
		index2=cli_to_prx[index2+1:].find('\n') +indextmp+1
		indextmp = index2
		index2=cli_to_prx[index2+1:].find('\n') +indextmp+1
		indextmp = index2
		index2=cli_to_prx[index2+1:].find('\n') +indextmp+1
		indextmp = index2
		index2=cli_to_prx[index2+1:].find('\n') +indextmp+1
		indextmp = index2
		index1=cli_to_prx[index2+1:].find('\n') + indextmp+1
		third = 'Connection: close'
		cli_to_prx = cli_to_prx.replace(cli_to_prx[index2+1:index1-1],third,1)
		data = 	cli_to_prx.encode()
		boolredi = 0
		return data,first,second						#return the orignal URL, HOST, data
	else :												# yonsei contain -> change the URL and HOST also change the connection
		first = 'http://www.linuxhowtos.org/ HTTP/1.1'
		index=cli_to_prx.find('GET')
		index2=cli_to_prx.find('\n')
		cli_to_prx = cli_to_prx.replace((cli_to_prx[index+4:index2-1]),(first),1)
		index=cli_to_prx.find('GET')
		index2=cli_to_prx.find('\n')
		indextmp = index2
		second = 'www.linuxhowtos.org'
		index=cli_to_prx[index2+1:].find('Host:')+indextmp
		index2=cli_to_prx[index2+1:].find('\n')+indextmp
		cli_to_prx = cli_to_prx.replace(cli_to_prx[index+7:index2],second,1)
		index=cli_to_prx.find('Host:')
		index2=cli_to_prx[index:].find('\n')+indextmp+1	
		indextmp = index2
		index2=cli_to_prx[index2+1:].find('\n') +indextmp+1
		indextmp = index2
		index2=cli_to_prx[index2+1:].find('\n') +indextmp+1
		indextmp = index2
		index2=cli_to_prx[index2+1:].find('\n') +indextmp+1
		indextmp = index2
		index2=cli_to_prx[index2+1:].find('\n') +indextmp+1
		indextmp = index2
		index1=cli_to_prx[index2+1:].find('\n') + indextmp+1
		third = 'Connection: close'
		cli_to_prx = cli_to_prx.replace(cli_to_prx[index2+1:index1-1],third,1)	
		data = 	cli_to_prx.encode()
		boolredi =1
		first ='GET http://www.linuxhowtos.org/ HTTP/1.1'
		return data,first,second						#return the change URL, HOST, and data

def print_log(ip,port,first,second,third,first1,size_res,first2,second2,getnum):			#print the whole log info
	global count
	global boolredi
	global boolimage

	count +=1

	print("----------------------------------")
	write = str(count) +' [Conn: '+  str(getnum) +'/'+str(threading.activeCount()-1)+']'
	print(write)
	
	urlf='X'
	imgf='X'
	if(boolredi ==1):
		urlf='O'
	else:
		urlf='X'
	if(boolimage ==1):
		imgf='O'
	else:
		imgf='X'																	#checking if the URL or image filter is happen or not
	print('[ '+str(urlf)+' ] ' + 'URL filter | [ '+ str(imgf)+' ] Image filter')
	print()
	newinfo = "[Cli connected to "+ip+":"+str(port)+"]"
	print(newinfo)
	print('[Cli ==> PRX --- SRV]')
	print('  > ' + first)
	print('  > ' + third)
	write = '[SRV connected to '+ second +':80]'
	print(write)
	print('[Cli --- PRX ==> SRV]')
	print('  > ' + first1)
	print('  > ' + third)
	print('[Cli --- PRX <== SRV]')
	print('  > ' + first2)
	print('  > ' + str(second2) +' '+ str(size_res)+'bytes')
	print('[Cli <== PRX --- SRV]')
	print('  > ' + first2)
	if(boolimage==1):
		print("  > Image filtering")
	else:
		print('  > ' + str(second2) +' '+ str(size_res)+'bytes')
	print("[SRV disconnected]")	
	print("[Cli disconnected]")
	


def threaded(client_socket, addr): 
	boolget =0
	global boolimage
	global boolredi
	global threadid

	data = client_socket.recv(4096)
	first=' '
	second=' '
	third=' '
	first1=' '
	first2=' '
	second2 =' '
	size_res =0

	try:
		if not data:
			client_socket.close() 
			#when the data is not exist
		else:
			first, second, third = prx_serv(data)	#find out the host, http, user-agent

			data ,first1, second1 = redirection(data,first,second) #After redirection (yonsei is contain) also change the connection keep-alive ->close


			if(first1 =='-1'):			#check get of not if -1 -> not get just send to host
				proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				if (second1 != '' or second1 !='-1'):
					proxy_socket.connect((second1,80))
					proxy_socket.send(data)
					while True:
						req_data = proxy_socket.recv(4096)
						client_socket.send(req_data)
						if not req_data:
							break
					proxy_socket.close()
							
			else:					#check when it is get
				boolget =1			#we can know the boolget by 1 when it is get option
				getnum =0
				for i in range(1,100):
					if (threadid[i] == 0):
						threadid[i] = -1
						getnum =i
						break
				proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				proxy_socket.connect((second1,80))
				proxy_socket.send(data)
				#connect to the destination server
				a=0
				signal =0
				while True:
					if(a==0):
						req_data = proxy_socket.recv(1024)			#get the data from the destinatio server
						total_dat = req_data
						first2, second2 = prx_cli(req_data)
						if(boolimage==1):
							first3,second3,req_data,signal = image_filter(req_data)
						client_socket.send(req_data)
				
					else:
						req_data = proxy_socket.recv(1024)
						cur1_dat = total_dat
						total_dat = cur1_dat+ req_data
						if(boolimage ==0 or signal == 0 ):
							client_socket.send(req_data)
					a +=1
					if not req_data:
						size_res =len(total_dat)

						break
				proxy_socket.close()
			client_socket.close()
			
			if (boolget==1):
				print_log(addr[0],addr[1],first,second,third,first1,size_res,first2,second2,getnum)	
				threadid[getnum] = 0
				
	except:
		proxy_socket.close()
		client_socket.close()

#start of the main

HOST = '127.0.0.1'
PORT = sys.argv[1]
print("Starting proxy server on port " + PORT)
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
		
		th_a =threading.Thread(target = threaded, args =(client_socket, addr)) 
		th_a.daemon= True		
		th_a.start()


#when the Keyboardinterrupt occuer
	except KeyboardInterrupt:	
		server_socket.close()
		print("")
		print('exit')
		break

server_socket.close() 
