# BleichenbacherSignatureForger
Forge PKCS1v1.5 signature for questionable implementation of verification algorithms...

Intro
-----

This repository contains a Python 2 implementation of the Bleichenbacher signature forgery attack. Having seen this variant of the attack multiple times during the last year both in CTFs and in real implementations showed the need for a more general solution than the hacky frankenstein scripts I have laying around.

Attack
------

PKCS1v15 is defined in https://www.ietf.org/rfc/rfc3447.txt. If the verification algorithm is trying to parse the result of the public key operation instead of building the expected data and comparing it to the result of the public key operation there is a possibility that it might be vulnerable to this attack.

Two variants of the attack will be supported:
- The length is not checked and a the padding is on the form 0001FFFFFFFFFFFFFFFF00 | DigestInfo | garbage
- The filler (PS) is not checked - 0001FFFFFFFFFFFFFFFF | garbage | 00 | DigestInfo

Usage
-----

``What, I don't know. There is no code yet!`` 

Will update Soon<sup>TM</sup>
