
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from binascii import a2b_base64

def extract_public_key(filename):
		
	#convert pem to der
	pem = open(filename).read()
	lines = pem.replace(" ",'').split()
	der = a2b_base64(''.join(lines[1:-1]))
	
	#extract subjectPublicKeyInfo field
	cert = DerSequence()
	cert.decode(der)
	tbsCertificate = DerSequence()
	tbsCertificate.decode(cert[0])
	subjectPublicKeyInfo = tbsCertificate[6]
	
	#initialize RSA key
	return  RSA.importKey(subjectPublicKeyInfo)
