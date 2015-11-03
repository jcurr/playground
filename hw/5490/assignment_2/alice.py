import socket
from Crypto import Random
import pickle
import sys

global msg
global nonce_b
global nonce_s
global chosen_cipher
global bob_cert
global cipher

hash_string = "CLIENT"

#produce random strings of bits for a nonce
nonce_a = Random.get_random_bytes(8)
print("NA = " + str(int(nonce_a.encode('hex'), 16)))

#produce random strings of bits for a nonce
nonce_s = Random.get_random_bytes(8)
print("NS = " + str(int(nonce_s.encode('hex'), 16)))

#set up socket
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost",port))

comm_state = 1
packet_size = 4096
while True:
	
	if comm_state == 1:
		req = "I want to talk to you"
		cipher_options = "ciphers i support"
		nonce = nonce_a
		msg = pickel.dumps([req, cipher_options, nonce_1])
		s.send(msg)
		comm_state += 1

	if comm_state == 2:
		msg = s.recv(packet_size)
		msg_arr = pickle.loads(msg)
		bob_cert = msg_arr[0]
		chosen_cipher = msg_arr[1]
		nonce_b = msg_arr[2]
		comm_state += 1

	if comm_state == 3:
		#encrypt nonce_s with bob's public key
		
		bob_public = getPublicKey(bob_cert)
		#compute keyed hash of use keyd SHA-1, append hash_string
		
		#s.send(msg)
		comm_state += 1

	
	if comm_state == 4:
		msg = s.recv(packet_size)

		comm_state += 1
	
	# data phase
	if comm_state == 5:
		
		
	
