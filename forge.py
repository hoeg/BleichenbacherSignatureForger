#!/usr/bin/python

import binascii
import hashlib
import gmpy2

HASH_ASN1 = {
'MD5': b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
'SHA-1': b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
'SHA-256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
'SHA-384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
'SHA-512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

keysize = 1024

def encodePkcs1Suffix(message):
	messageHash = hashlib.sha1(message).digest()
	if messageHash[-1] & 0x01 != 0x01:
		print("hash value must be uneven. Try a different message")
		exit()
	suffix = "\x00" + HASH_ASN1["SHA-1"] + messageHash
	return suffix

def getBitAt(idx, val):
	return (val >> (idx - 1)) & 0x01

def setBitAt(idx, val):
	return val | (0x01 << (idx - 1))


def constructSignatureSuffix(suffix):
	signatureSuffix = 1
	for idx in range(len(suffix) * 8):
		if getBitAt(idx, signatureSuffix ** 3) != getBitAt(idx, suffix):
			signatureSuffix = setBitAt(idx signatureSuffix)
	return signatureSuffix

def toInt(val):
	return int(val.encode("hex"), 16)

def toBytes(val):
	return hex(val)[2,-1].decode("hex")

def addPrefixTosignature(signatureSuffix):
	prefix = "\x00\x01"
	prefix += "\xFF"*8
	while True:
		testPrefix = prefix + os.urandom((keysize/8) - (len(prefix))
		signatureCandidate = toBytes(gmpy2.cbrt(int(testPrefix, 16))) + "\x00" + signatureSuffix
		toCheck = toBytes(toInt(signatureCandidat) ** 3)[:-len(signatureSuffix)+1]
		if "\x00" not in toCheck:
			return signatureCandidate


def forgeSignature(message):
	suffix = encodePkcs1Suffix(message)
	signatureSuffix = constructSignatureSuffix(suffix)
	signature = addPrefixToSignature(signatureSuffix)
	return signature

if __name__ == "__main__":
	message = "WhatWhatInTheButt"
	signature = forgeSignature(message)
	'''
	output format: raw, hex, base64
	keysize: raw, from public key
	hash algo, md5, sha1, sha256, sha384, sha512
	message to sign: ascii, hex, base64
	'''

