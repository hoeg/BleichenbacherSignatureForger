#!/usr/bin/python

import hashlib

HASH_ASN1 = {
'MD5': b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
'SHA-1': b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
'SHA-256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
'SHA-384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
'SHA-512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

class Hash:

	def __init__(self, hashAlg):
		if hashAlg == "MD5":
			self.digestInfo = HASH_ASN1[hashAlg]
			self.digester = hashlib.md5
		elif hashAlg == "SHA-1":
			self.digestInfo = HASH_ASN1[hashAlg]
			self.digester = hashlib.sha1
		elif hashAlg == "SHA-256":
			self.digestInfo = HASH_ASN1[hashAlg]
			self.digester = hashlib.sha256
		elif hashAlg == "SHA-384":
			self.digestInfo = HASH_ASN1[hashAlg]
			self.digester = hashlib.sha384
		elif hashAlg == "SHA-512":
			self.digestInfo = HASH_ASN1[hashAlg]
			self.digester = hashlib.sha512
		else:
			raise Exception("Invalid hash algorithm identifier provided")

