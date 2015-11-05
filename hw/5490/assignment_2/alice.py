import socket
from Crypto.Random import random
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import DES3
from Crypto.Hash import HMAC, SHA
import pickle
import sys
from common_util import * 

global msg_1
global msg_2
global msg_3
global msg_4
global nonce_b
global nonce_a
global chosen_cipher
global bob_cert
global cipher
global master_secret
global bob_public_cipher

no_errors = True

my_public_key = extract_public_key('alice_cert.pem')
my_private_key = RSA.importKey(open('private_alice.pem').read())
my_private_cipher = PKCS1_v1_5.new(my_private_key)
my_public_cipher = PKCS1_v1_5.new(my_public_key)

hash_string = "CLIENT"

#produce random strings of bits for a nonce

nonce_a = random.getrandbits(64)
print("NA = " + str(nonce_a))

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
		my_cert_string = open("alice_cert.pem").read()

		#nonce_a = bob_public_cipher.encrypt(nonce_a)
		msg_1 = pickle.dumps([req, cipher_options, my_cert_string])

		s.send(msg_1)
		print_state_data(comm_state, "send: [I wan't to talk to you, [my ciphers], my certificate]")
		comm_state += 1

	if comm_state == 2:
		msg_2 = s.recv(packet_size)
		msg_arr = pickle.loads(msg_2)
				
		bobs_cert_string = msg_arr[0]
		bob_cert = open('cert_from_bob.pem', 'w')
		bob_cert.write(bobs_cert_string)
		bob_cert.close()
		bob_public_key = extract_public_key("cert_from_bob.pem")
		bob_public_cipher = PKCS1_v1_5.new(bob_public_key)
		chosen_cipher = msg_arr[1]

		nonce_b_cipher_text = msg_arr[2]
		sentinel = Random.new().read(15+len(nonce_b_cipher_text))
		nonce_b = my_private_cipher.decrypt(nonce_b_cipher_text, sentinel)

		print_state_data(comm_state,"recv:\tmy certificate\n\tchosen cipher\n\tKa+{" + str(nonce_b) + "}")
		comm_state += 1

	if comm_state == 3:
		
		a = nonce_a
		b = long(nonce_b)
		master_secret = a ^ b
		
		secret = "Master Secret created = " + str(master_secret)
		
		encrypted_nonce = bob_public_cipher.encrypt(str(nonce_a))
		
		to_digest = str(master_secret) + msg_1 + msg_2 + hash_string
		digest = HMAC.new(bytes(master_secret), to_digest, SHA.new() )
		digest = digest.hexdigest()
		
		msg_3 = pickle.dumps([encrypted_nonce, digest])	
		s.send(msg_3)
		print_state_data(comm_state, "send:\tK+bob{"+ str(nonce_a) + "}" + "\n\tdigest = " + digest + "\n" + secret)
		comm_state += 1

	
	if comm_state == 4:
		msg_4 = s.recv(packet_size)
		msg_arr = pickle.loads(msg_4)
	
		bobs_hash = msg_arr[0]	
		to_digest = str(master_secret) + msg_1 + msg_2 + msg_3 + "SERVER"
		digest = HMAC.new(bytes(master_secret), to_digest, SHA.new() )
		digest = digest.hexdigest()

		result = 'Success - Keyed Hashes matched'
		if bobs_hash != digest:
			result = 'Error - Hashes did not match *******************'
			no_errors = False
		
		print_state_data(comm_state, "recv: digest = " + digest + "\n" + result)
		comm_state += 1

	# data phase
	if comm_state == 5:
				
		comm_state += 1
		break
s.close()
if no_errors:
	print '\n\nNo Errors detected, have a nice day :)\n'	
else:
	print 'Warning - Errors detected'	
