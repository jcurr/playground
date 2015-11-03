import socket
from Crypto import Random
import pickle
import sys

global msg
global nonce_b
global nonce_a
global chosen_cipher
global alice_cert
global cipher
global master_secret

hash_string = "SERVER"

#produce random strings of bits for a nonce
nonce_b = Random.get_random_bytes(8)
print("NB = " + str(int(nonce_b.encode('hex'), 16)))

#set up socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print 'Socket created for Bob'
port = sys.argv[1]
s.bind(("localhost", int(port)))
s.listen(10)


comm_state = 0
packet_size = 4096
while True:
	
	if comm_stat == 0:
		#Accept a connection from Alice
		conn, addr = s.accept()
		comm_state += 1
		
	if comm_state == 1:
		#Receive Alice's request: ["I wan't to talk to you", Alice's ciphers, nonce_alice]
		msg = s.recv(packet_size)
		msg_arr = pickle.loads(msg)
	
		#Disregarding first item of incoming array "I want to talk to you"
		
		#Retreive Alice's cipher suite
		ciphers_supported_by_alice = msg_arr[1]
		#Choose a cipher
		chosen_cipher = choose_cipher(ciphers_supported_by_alice)	
		#Instantiate the cipher object for Bob
		#cipher = 
		
		#Retreive Alice's nonce
		nonce_a = msg_arr[2]

		comm_state += 1

	if comm_state == 2:
		#Send Bob's certificate to alice, Bob's selected cipher and Bob's nonce
		msg = pickle.dumps([my_cert, chosen_cipher, nonce_b])
		s.send(msg)
		comm_state += 1

	if comm_state == 3:
		msg = s.recv(packet_size)
		msg_arr = pickle.loads(msg)
		
		#master_secret = cipher.decrypt(msg_arr[0])
		
		#keyed_hash =
		bob_public = getPublicKey(bob_cert)
		#compute keyed hash of use keyd SHA-1, append hash_string
		
		s.send("hello") #s.send(msg)
		comm_state += 1

	
	if comm_state == 4:
		msg = s.recv(packet_size)
	
		comm_state += 1

	# data phase
	if comm_state == 5:
		
		comm_state += 1
		
	
