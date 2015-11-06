import socket
from Crypto import Random
from Crypto.Random import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA
import pickle
import sys
from common_util import * 
import OpenSSL
import subprocess

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
global my_dec_key
global my_verify_key
global iv

no_errors = True

my_public_key = RSA.importKey(open('public_bob.pem').read())
my_private_key = RSA.importKey(open('private_bob.pem').read())
my_private_cipher = PKCS1_v1_5.new(my_private_key)
my_public_cipher = PKCS1_v1_5.new(my_public_key)

hash_string = "SERVER"

nonce_b = Random.get_random_bytes(32)
nonce_b_int = int(nonce_b.encode('hex'), 16)
print("Nb = " + str(nonce_b_int))

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
		print_state_data(comm_state, "Accepted Connection")
		comm_state += 1
		continue
		
	if comm_state == 1:
		#Receive Alice's request: ["I wan't to talk to you", Alice's ciphers, certificate_alice]
		msg_1 = conn.recv(packet_size)
		msg_arr = pickle.loads(msg_1)

		#Disregarding first item of incoming array "I want to talk to you"
		
		#Retreive Alice's cipher suite
		ciphers_supported_by_alice = msg_arr[1]
		#Choose a cipher
		#chosen_cipher =  choose_cipher(ciphers_supported_by_alice)	
		
		#Retreive Alice's certificate
		alices_cert_string = msg_arr[2]
		alice_cert = open('cert_from_alice.pem', 'w')
		alice_cert.write(alices_cert_string)
		alice_cert.close()	
	
		alice_public_key = subprocess.check_output(["openssl","req","-in","cert_from_alice.pem","-noout","-pubkey"])
		alice_public_key = RSA.importKey(alice_public_key)

		alice_csr = OpenSSL.crypto.load_certificate_request(OpenSSL.crypto.FILETYPE_PEM, alices_cert_string)
		
		result ="Success - Alice's cert was verified"
		if not alice_csr.verify(alice_csr.get_pubkey()):
			result = "Error - Alice's cert not verifed ******"
			no_errors = False
		
		alice_public_cipher = PKCS1_v1_5.new(alice_public_key)
		
		print_state_data(comm_state, "recv: [I wan't to talk to you, [Alice's ciphers], certificate_alice]")
		comm_state += 1
		continue

	if comm_state == 2:
		#Send Bob's certificate to alice, Bob's selected cipher and Bob's nonce
		my_cert = open("b_cert.pem").read()
		
		encrypted_nonce = alice_public_cipher.encrypt(str(nonce_b))
		
		msg_2 = pickle.dumps([my_cert, "chosen_cipher", encrypted_nonce])
		
		conn.send(msg_2)
		print_state_data(comm_state,"send:\tmy certificicate\n\tchosen cipher\n\tKa+{" + str(nonce_b) + "}" + result)
		comm_state += 1
		continue

	if comm_state == 3:
		msg_3 = conn.recv(packet_size)
		msg_arr = pickle.loads(msg_3)
		
		nonce_a_cipher_text = msg_arr[0]
		sentinel = Random.new().read(15+len(nonce_a_cipher_text))
		nonce_a = my_private_cipher.decrypt(nonce_a_cipher_text, sentinel)
		
		
		nonce_a_int = int(nonce_a.encode('hex'), 16)
		a = nonce_a_int
		b = nonce_b_int
		master_secret = a ^ b

		secret = "Master Secret created = " + str(master_secret)
		
		to_digest = str(master_secret) + msg_1 + msg_2 +"CLIENT" 
		digest = HMAC.new(bytes(master_secret), to_digest, SHA.new() )
		digest = digest.hexdigest()
		
		alices_hash = msg_arr[1]
		
		result = 'Success - Keyed Hashes matched'
		if alices_hash != digest:
			result = 'Error - Hashes did not match *******************'
			no_errors = False
		
		print_state_data(comm_state, "recv:\tnonce_alice = " + str(nonce_a) + "\n\tdigest = " + digest + "\n" + secret + "\n" + result)
		comm_state += 1
		continue
	
	if comm_state == 4:
	
		to_digest = str(master_secret) + msg_1 + msg_2 + msg_3 + hash_string
		digest = HMAC.new(bytes(master_secret), to_digest, SHA.new() )
		digest = digest.hexdigest()
		
		msg_4 = pickle.dumps([digest])
		conn.send(msg_4)

		keys = generate_keys(master_secret, hash_string)
		my_enc_key = keys[0]
		my_dec_key = keys[1]
		my_auth_key = keys[2]
		my_verify_key = keys[3]
		iv = keys[4]

		print(my_enc_key + " " +  my_dec_key + " " + my_auth_key + " " + my_verify_key)

		print_state_data(comm_state, "send: digest = " + digest)
		comm_state += 1
		continue

	# data phase
	if comm_state == 5:
		incoming = open("incoming_transfer.txt", "w")
		msg = conn.recv(packet_size)
		header = msg[:5]
		msg = msg[5:]	
		while msg:
			incoming.write(msg)
			msg = conn.recv(packet_size)
		incoming.close()

		cipher_text = open("incoming_transfer.txt").read()

		session_cipher = AES.new(my_dec_key, AES.MODE_CBC, iv)	
		plain_text = session_cipher.decrypt(cipher_text)
		plain_text = remove_padding(plain_text)
	
		plain_file = open("incoming_transfer.txt","w")
		plain_file.write(plain_text[:-40])
		plain_file.close()		
		to_digest = plain_text[:-40]
		digest = HMAC.new(bytes(my_verify_key), to_digest, SHA.new() )
		digest = digest.hexdigest()
		
		alice_digest = plain_text[-40:]
		result = 'Success - Keyed Hashes matched'
		if alice_digest != digest:
			result = 'Error - Hashes did not match *******************'
			no_errors = False
		
		print_state_data(comm_state, "recv: file\n" + result)
		break
s.close()
if no_errors:
	print '\n\nNo Errors Detected, Have a Nice Day :)\n'
else:
	print 'Warning - Errors detected'	
