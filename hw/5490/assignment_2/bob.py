import socket
from Crypto import Random
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import DES3
import pickle
import sys
from binascii import a2b_base64
import subprocess
from common_util import * 

global msg
global nonce_b
global nonce_a
global chosen_cipher
global alice_cert
global cipher
global master_secret

my_cert = open("bob_cert.pem").read()

#my_public_key = extract_public_key('bob_cert.pem')
#my_private_key = RSA.importKey(open('private_bob.pem').read())
#print(repr(my_private_key))

#my_private_cipher = PKCS1_v1_5.new(my_private_key)

alice_public_key = extract_public_key("alice_cert.pem")
alice_public_cipher = PKCS1_v1_5.new(alice_public_key)
#print(alice_public_key)



my_public_key = extract_public_key('bob_cert.pem')
my_private_key = RSA.importKey(open('private_bob.pem').read())
my_private_cipher = PKCS1_v1_5.new(my_private_key)
my_public_cipher = PKCS1_v1_5.new(my_public_key)



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
	
	if comm_state == 0:
		#Accept a connection from Alice
		conn, addr = s.accept()
		print("connected to alice")
		comm_state += 1
		continue
		
	if comm_state == 1:
		#Receive Alice's request: ["I wan't to talk to you", Alice's ciphers, nonce_alice]
		msg = conn.recv(packet_size)
		print("received packet")
		msg_arr = pickle.loads(msg)
		#Disregarding first item of incoming array "I want to talk to you"
		
		#Retreive Alice's cipher suite
		ciphers_supported_by_alice = msg_arr[1]
		#Choose a cipher
		#chosen_cipher =  choose_cipher(ciphers_supported_by_alice)	
		#Instantiate the cipher object for Bob
		#cipher = 
		
		#Retreive Alice's nonce
		nonce_a = msg_arr[2]
		sentinel = Random.new().read(15+len(nonce_a))
		decrypted = my_private_cipher.decrypt(nonce_a,sentinel)
		print(str( int(decrypted.encode('hex'),16)))
		comm_state += 1
		continue

	if comm_state == 2:
		#Send Bob's certificate to alice, Bob's selected cipher and Bob's nonce
		encrypted_nonce = alice_public_cipher.encrypt(nonce_b)
		print(encrypted_nonce)
		msg = pickle.dumps([my_cert, "chosen_cipher", encrypted_nonce])
		conn.send(msg)
		comm_state += 1
		continue

	if comm_state == 3:
		msg = conn.recv(packet_size)
		msg_arr = pickle.loads(msg)
		
		#master_secret = cipher.decrypt(msg_arr[0])
		
		#keyed_hash =
		bob_public = extract_public_key(bob_cert)
		#compute keyed hash of use keyd SHA-1, append hash_string
		
		conn.send("hello") #s.send(msg)
		comm_state += 1
		continue
	
	if comm_state == 4:
		msg = conn.recv(packet_size)
	
		comm_state += 1
		continue
	# data phase
	if comm_state == 5:
		
		comm_state += 1
		continue
	
