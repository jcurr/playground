import socket
from Crypto import Random
from Crypto.Random import random
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import DES3
from Crypto.Hash import HMAC, SHA
import pickle
import sys
from binascii import a2b_base64
import subprocess
from common_util import * 
from OpenSSL import crypto
from Crypto import Signature
global msg_1
global msg_2
global msg_3
global msg_4
global nonce_b
global nonce_a
global chosen_cipher
global alice_cert
global cipher
global master_secret
global alice_public_cipher

my_cert = open("bob_cert.pem").read()

#my_public_key = extract_public_key('bob_cert.pem')
#my_private_key = RSA.importKey(open('private_bob.pem').read())
#print(repr(my_private_key))
alice_cert_string = open("alice_cert.pem").read()
alice_cert = crypto.load_certificate(crypto.FILETYPE_PEM, alice_cert_string)
print(repr(alice_cert))
alice_pub = alice_cert.get_pubkey()

print(repr(alice_pub))
print(str(alice_pub))

alice_key_string = open("private_alice.pem").read()
alice_key = crypto.load_privatekey(crypto.FILETYPE_PEM, alice_key_string)
print(repr(alice_key))

alice_cert.sign(alice_key,"sha1")

my_public_key = extract_public_key('bob_cert.pem')
my_private_key = RSA.importKey(open('private_bob.pem').read())
my_private_cipher = PKCS1_v1_5.new(my_private_key)
my_public_cipher = PKCS1_v1_5.new(my_public_key)



hash_string = "SERVER"

#produce random strings of bits for a nonce
nonce_b = random.getrandbits(64)
print("NA = " + str(nonce_b))

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
		#Receive Alice's request: ["I wan't to talk to you", Alice's ciphers, certificate_alice]
		msg_1 = conn.recv(packet_size)
		print("received packet")
		msg_arr = pickle.loads(msg_1)
		#Disregarding first item of incoming array "I want to talk to you"
		
		#Retreive Alice's cipher suite
		ciphers_supported_by_alice = msg_arr[1]
		#Choose a cipher
		#chosen_cipher =  choose_cipher(ciphers_supported_by_alice)	
		#Instantiate the cipher object for Bob
		#cipher = 
		
		#Retreive Alice's certificate
		alices_cert_string = msg_arr[2]
		alice_cert = open('cert_from_alice.pem', 'w')
		alice_cert.write(alices_cert_string)
		alice_cert.close()	
		alice_public_key = extract_public_key("cert_from_alice.pem")
		alice_public_cipher = PKCS1_v1_5.new(alice_public_key)
		
		
	#	sentinel = Random.new().read(15+len(nonce_a))
	#	decrypted = my_private_cipher.decrypt(nonce_a,sentinel)
	#	print(str( int(decrypted.encode('hex'),16)))
		comm_state += 1
		continue

	if comm_state == 2:
		#Send Bob's certificate to alice, Bob's selected cipher and Bob's nonce
		encrypted_nonce = alice_public_cipher.encrypt(str(nonce_b))
	#		print(encrypted_nonce)
		msg_2 = pickle.dumps([my_cert, "chosen_cipher", encrypted_nonce])
		conn.send(msg_2)
		comm_state += 1
		continue

	if comm_state == 3:
		msg_3 = conn.recv(packet_size)
		msg_arr = pickle.loads(msg_3)
		
		nonce_a_cipher_text = msg_arr[0]
		sentinel = Random.new().read(15+len(nonce_a_cipher_text))
		nonce_a = my_private_cipher.decrypt(nonce_a_cipher_text, sentinel)
		
		print(nonce_a)
		
		a = long(nonce_a)
		b = nonce_b
		master_secret = a ^ b
		print(str(master_secret))
		
		to_digest = str(master_secret) + msg_1 + msg_2 +"CLIENT" 
		digest = HMAC.new(bytes(master_secret), to_digest, SHA.new() )
		digest = digest.hexdigest()
		print(digest)
		
		alices_hash = msg_arr[1]
		
		if alices_hash != digest:
			print 'hashs did not match'
		else:
			print 'hashs did match'
		
		comm_state += 1
		continue
	
	if comm_state == 4:
	#	msg = conn.recv(packet_size)
	
		to_digest = str(master_secret) + msg_1 + msg_2 + msg_3 + hash_string
		digest = HMAC.new(bytes(master_secret), to_digest, SHA.new() )
		digest = digest.hexdigest()
		print(digest)
		
		msg_4 = pickle.dumps([digest])
		conn.send(msg_4)
		comm_state += 1
		continue

	# data phase
	if comm_state == 5:
		
		comm_state += 1
		continue
	
