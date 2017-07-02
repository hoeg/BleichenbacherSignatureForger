#!/usr/bin/python

import argparse

from HashInfo import *
from SignatureForger import *

def printOutput(signature):
  print("****************************************************")
  print("*         Signature successfully generated!        *")
  print("****************************************************")
  print("")
  print("Signature:")
  print(hex(signature))
  print("Plaintext:")
  print(hex(toInt(signature) ** 3))


def getArguments():
  parser = argparse.ArgumentParser(description="Signature forger for RSA PKCS1v1.5 given that the exponent 3 is used and the verification algorithm is not implemented properly")

  parser.add_argument("-k", "--keysize", type=int)
  parser.add_argument("-ha", "--hashalg", action="store", type=str, choices=list(HASH_ASN1.keys()))
  parser.add_argument("-va", "--variant", type=int, choices=[1,2])
  parser.add_argument("-of", "--outputformat", type=str, choices=["hex", "base64", "raw"])
  parser.add_argument("-m", "--message", type=str)

  args = parser.parse_args()
  return args

if __name__ == "__main__":

  args = getArguments()

  keySize = args.keysize
  hashAlg = args.hashalg

  signatureForger = SignatureForger(keySize, hashAlg)

  signature = ""

  if args.variant == 1:
    signature = signatureForger.forgeSignature_method1(args.message)
  elif args.variant == 2:
    signature = signatureForger.forgeSignature_method2(args.message)
  else:
    raise Exception("Unsupported signature method") 

  printOutput(signature)
