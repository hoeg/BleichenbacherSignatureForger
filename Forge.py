#!/usr/bin/python

import argparse

from HashInfo import *
from SignatureForger import *

if __name__ == "__main__":
  parser = argparse.ArgumentParser(description="Signature forger for RSA PKCS1v1.5 given that the exponent 3 is used and the verification algorithm is not implemented properly")

  keySize = 0
  hashAlg = None

  signatureForger = SignatureForger(keySize, hashAlg)
