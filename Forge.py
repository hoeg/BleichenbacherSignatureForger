#!/usr/bin/python

import argparse

from HashInfo import *
from SignatureForger import *

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Signature forger for RSA PKCS1v1.5 given that the exponent 3 is used and the verification algorithm is not implemented properly")

  parser.add_argument("-k", "--keysize", type=int)
  parser.add_argument("-ha", "--hashalg", action="store", type=str, choices=list(HASH_ASN1.keys()))
  parser.add_argument("-m", "--message", type=str)

  args = parser.parse_args()

  keySize = args.keysize
  hashAlg = args.hashalg

  signatureForger = SignatureForger(keySize, hashAlg)

  signature = signatureForger.forgeSignature_method2(args.message)
  print(hex(toInt(signature) ** 3))

