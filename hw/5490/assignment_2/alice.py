import socket
from Crypto.Random import random
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA
import pickle
import sys
from common_util import * 
import subprocess
import OpenSSL

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
global my_enc_key
global my_auth_key
global iv

no_errors = True
my_public_key = RSA.importKey(open('public_alice.pem').read())

my_private_key = RSA.importKey(open('private_alice.pem').read())
my_private_cipher = PKCS1_v1_5.new(my_private_key)
my_public_cipher = PKCS1_v1_5.new(my_public_key)

hash_string = "CLIENT"

#produce random strings of bits for a nonce

nonce_a = Random.get_random_bytes(32)
nonce_a_int = int(nonce_a.encode('hex'), 16)
print("Na = " + str(nonce_a_int))

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
		my_cert_string = open("a_cert.pem").read()

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
		
		bob_public_key = subprocess.check_output(["openssl","req","-in","cert_from_bob.pem","-noout","-pubkey"])
		bob_public_key = RSA.importKey(bob_public_key)
		bob_public_cipher = PKCS1_v1_5.new(bob_public_key)

		bob_csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, bobs_cert_string)
		
		result ="Success - Bob's cert was verified"
		if not bob_csr.verify(bob_csr.get_pubkey()):
			result = "Error - Bob's cert not verifed ******"
			no_errors = False

		chosen_cipher = msg_arr[1]

		nonce_b_cipher_text = msg_arr[2]
		sentinel = Random.new().read(15+len(nonce_b_cipher_text))
		nonce_b = my_private_cipher.decrypt(nonce_b_cipher_text, sentinel)

		nonce_b_int = int(nonce_b.encode('hex'), 16)
		print_state_data(comm_state,"recv:\tmy certificate\n\tchosen cipher\n\tKa+{" + str(nonce_b) + "}" + "\n" + result)
		comm_state += 1

	if comm_state == 3:
		
		a = nonce_a_int
		b = nonce_b_int
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
		
		keys = generate_keys(master_secret, hash_string)
		my_enc_key = keys[0]
		my_dec_key = keys[1]
		my_auth_key = keys[2]
		my_verify_key = keys[3]
		iv = keys[4]
	
		print(my_enc_key + " " +  my_dec_key + " " + my_auth_key + " " + my_verify_key)
			
		print_state_data(comm_state, "recv: digest = " + digest + "\n" + result)
		comm_state += 1

	# data phase
	if comm_state == 5:
		
		file_to_send = open("original_file.txt").read()
		to_digest = file_to_send
		digest = HMAC.new(my_auth_key, to_digest, SHA.new())
		digest = digest.hexdigest()
		
		session_cipher = AES.new(my_enc_key, AES.MODE_CBC, iv)	
		plain_text = file_to_send + digest
		plain_text = add_padding(plain_text)
		cipher_text = session_cipher.encrypt(plain_text)
		
		header = b'cMmll'	
		s.send(header + cipher_text)				
		comm_state += 1
		break
s.close()
if no_errors:
	print '\n\nNo Errors detected, have a nice day :)\n'	
else:
	print 'Warning - Errors detected'	
