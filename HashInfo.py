#! /usr/bin/env python3


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

from hashlib import md5, sha1, sha224, sha256, sha384, sha512

HASH_ASN1 = {
    "MD5": b"\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10",
    "SHA-1": b"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14",
    "SHA-224": b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1C",
    "SHA-256": b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
    "SHA-384": b"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
    "SHA-512": b"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
}


class Hash:
    def __init__(self, hashAlg):
        if hashAlg == "MD5":
            self.digestInfo = HASH_ASN1[hashAlg]
            self.digester = md5
        elif hashAlg == "SHA-1":
            self.digestInfo = HASH_ASN1[hashAlg]
            self.digester = sha1
        elif hashAlg == "SHA-224":
            self.digestInfo = HASH_ASN1[hashAlg]
            self.digester = sha224
        elif hashAlg == "SHA-256":
            self.digestInfo = HASH_ASN1[hashAlg]
            self.digester = sha256
        elif hashAlg == "SHA-384":
            self.digestInfo = HASH_ASN1[hashAlg]
            self.digester = sha384
        elif hashAlg == "SHA-512":
            self.digestInfo = HASH_ASN1[hashAlg]
            self.digester = sha512
        else:
            raise Exception("Invalid hash algorithm identifier provided")
