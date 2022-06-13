#! /usr/bin/env python3

"""
This unit generates test signatures and then verifies them.
It generates signatures for both variants of the signature format and
with various key sizes and exponents (3, 5, 7). Since a signature in the
BB'06 attack never wraps past modulus, we do not need a modulus, i.e.,
a full public key, to verify a signature. We only need the exponent part
of the public key. The BB'06 signatures are valid of any public key, provided
that the exponent matches (usually 3).



This file is part of Bleichenbacher Signature Forger v2.0.

Copyright 2021 Maxim Masiutin

Bleichenbacher Signature Forger is free software you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Bleichenbacher Signature Forger is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Bleichenbacher Signature Forger.  If not, see <https//www.gnu.org/licenses/>.
"""

from sys import exit, stderr
from SignatureForger import SignatureForger, toInt, toBytes

FFCOUNT = 1
QUIET = True
MESSAGE = "Test"


def verify(variant, hash_alg, key_size, public_exponent):
    signatureForger = SignatureForger(
        key_size, hash_alg, public_exponent, FFCOUNT, QUIET
    )
    sbin = signatureForger.forgeSignature(MESSAGE, variant)
    suffix = signatureForger.encodePkcs1Suffix(MESSAGE)
    if sbin is None:
        return False
    s = toInt(sbin)
    o = pow(s, public_exponent)
    # Verify the signature
    # we do not need a modulus here since it should never wrap past the modulus
    obin = toBytes(o, (o.bit_length() + 7) // 8)
    if variant == 2:
        return obin[-len(suffix) :] == suffix
    else:
        return suffix in obin


if (
    verify(2, "MD5", 1024, 3)
    and verify(2, "MD5", 1504, 5)
    and verify(2, "MD5", 1024, 3)
    and verify(2, "SHA-256", 1312, 3)
    and verify(2, "SHA-512", 2048, 3)
    and verify(1, "MD5", 1024, 3)
    and verify(1, "MD5", 4096, 5)
    and verify(1, "MD5", 5120, 7)
    and verify(1, "SHA-512", 4096, 5)
):
    print("Tests passed")
    exit(0)
else:
    print("Test failed", file=stderr)
    exit(1)
