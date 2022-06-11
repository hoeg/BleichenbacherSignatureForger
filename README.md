# Bleichenbacher BB'06 RSA Signature Tool

Generate a valid RSA signature without a key.

## Intro

This repository contains a Python 3 implementation of the Bleichenbacher signature forgery attack, described in 2006 (BB'06 attack). Having seen this variant of the attack multiple times during the last year both in CTFs and in real implementations showed the need for a more general solution than the hacky frankenstein scripts, Peter Hoeg Steffensen have laying around. Maxim Masiutin has updated this tool to solve a challenge published in 2020 on an Information Security learning platform, to generate a signature for a key of 2736 bits (e=3) without having the private key. Public modulus (N) is also not needed for the BB'06 signature generation.

## Attack

PKCS #1 v1.5 is defined in <https://www.ietf.org/rfc/rfc3447.txt>. If the verification algorithm is trying to parse the result of the public key operation instea>

Two variants of the attack are supported:

1. The length is not checked, and the padding is on the form ``0001FF...FF00 | DigestInfo | garbage``
2. The filler (PS) is not checked - ``0001FF...FF | non-zero-garbage | 00 | DigestInfo``

More info on variant 1 can be found at: <https://www.ietf.org/mail-archive/web/openpgp/current/msg00999.html>

Credit for variant 2 goes to Filippo Valsorda, who published the original version of the code in 2016 (<https://blog.filippo.io/bleichenbacher-06-signature-for>

Since a signature in the BB'06 attack never wraps past modulus, we do not need a modulus, i.e., a full public key, to verify a signature. We only need the exponent part of the public key. The BB'06 signatures are valid of any public key, provided that the exponent matches (usually 3).
## Usage

```
$ python Forge.py --help

usage: Forge.py [-h] [-k KEYSIZE] [-ha {MD5,SHA-1,SHA-256,SHA-384,SHA-512}] [-va {1,2}] [-of {decimal,hex,base64,raw}] [-m MESSAGE] [-e PUBLIC_EXPONENT] [-F FFCOUNT] [-q]

Bleichenbacher Signature Forger. Version 2.0. This program demonstrates the vulenrability of the RSA PKCS1v1.5 and the attack when public exponent is small (e.g., 3) and the verification
algorithm is not implemented properly.

optional arguments:
  -h, --help            show this help message and exit
  -k KEYSIZE, --keysize KEYSIZE
  -ha {MD5,SHA-1,SHA-256,SHA-384,SHA-512}, --hashalg {MD5,SHA-1,SHA-256,SHA-384,SHA-512}
  -va {1,2}, --variant {1,2}
                        1 - 00 01 FF ... 00 ASN.1 HASH GarbageWithZeros; 2 - 00 01 FF NonzeroGarbage 00 ASN.1 HASH
  -of {decimal,hex,base64,raw}, --outputformat {decimal,hex,base64,raw}
  -m MESSAGE, --message MESSAGE
  -e PUBLIC_EXPONENT, --public-exponent PUBLIC_EXPONENT
  -F FFCOUNT, --ffcount FFCOUNT
  -q, --quiet
```
## Example
```
./Forge.py --keysize 2048 -ha SHA-256 --variant 2 --message "Test"
```

## History

- 1.0 (July 2nd, 2017)
  - Initial version

- 2.0 (May 5th, 2021)
  - Ported to Python 3
  - Removed strings in favor of byte objects
  - Added support for output formats
  - Added support for the public exponent command line parameter
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


