Stego
=====

Stego is a tool and library for steganographic hiding of data into large random files.

An empty bitfile named dataplate of 10^9 bytes is created with command:
java -jar stego.jar dataplate -c 1G

File payload.txt is written into bitfile dataplate with command:
java -jar stego.jar dataplate -w payload.txt

File payload.txt is read to stdout from bitfile dataplate with command:
java -jar stego.jar dataplate -r -payload.txt


Concepts
--------

BITFILE is a large file filled with cryptographically secure random data.

PLAINTEXT or PAYLOAD is the normal data that is to be hidden.

PASSCODE is a the name associated with the plaintext that is to be hidden. Required keys are derived so that they can be recovered by just knowing the passcode.

CIPHER TRAIL is two different ciphers derived from 32 byte long random key or passcode, address cipher and data cipher. Both ciphers are AES 256 ciphers, their keys and initialization vectors are got from the passcode or a random key with Argon2 hash to slow down the guessing of passcodes.

ADDRESS CIPHER tells what is the 64 bit position of in the bitfile where the current bit is associated to. Position will be normalized to actual position by taking modulo of it with the length of bitfile in bits.

DATA CIPHER is the regular crypto mask for the current bit, data bit is taken xor with it.

ARMOR CODE is a way to add error correction to the plaintext before steganographic distribution, so that data destruction by later steganographic distribution writes becomes less likely. Stego uses [Reed-Solomon error correction](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction) on first layer and under than [Hamming error correction](https://en.wikipedia.org/wiki/Hamming_code) under it.

METADATA is a label that contains the key of cipher trail where data is actually written. It is preceded with 8 bytes full of 1s and after it is placed the length of plaintext.

TAILING is random amount of random bytes that is attached in the end of the passcode to make it logically impossible to prove that given target passcode does not correspond to any steganographic data in the bitfile.

How it works
------------

WRITING a stegofile happens so that first a 32 byte long random key is picked with SecureRandom() and from that with Argon2 address cipher and data cipher and their initialization vectors are deduced for the cipher trail. The plaintext is first gzipped to reduce its size, and the result is then first armored with Reed-Solomon error correction and that result with Hamming error correction, and that result is distributed to locations address cipher points and encrypted with data cipher.

After the payload has been written, the runway of 8 bytes of all-1s, the 32 byte long random key for it and the length of plaintext data in bytes as java long (8 bytes) is written into a metadata label to ciphertrail that is got from the passcode or the name of the source file. Argon2 is fed the passcode/filenam in UTF-8 and with additional tailing random bytes. The amount of additional random bytes is in itself random, it is the count of immediate continuous 1s from SecureRandom, so there is a half and half chance to get another tailing byte. The content and amount of these bytes is not told to the user and is to be scrubbed after writing. This is done with the intent that no reader can ever be certain that there could not be a payload hidden related to a passcode in the bitfile, as it could just have longer tailing than so far has been tried. User can set a minimum amount for the tailing bytes with -n command.

READING a stegofile happens in the opposite order. Tailings are tried starting from 0 bytes and then increasing the count and bruteforcing through each possible tailing by trying if passcode and current tailing result in ciphertrail that starts with 8 bytes that are all-1s. After such ciphertrail is found, the whole metadata label, which contains the actual data key and data length, is read from the metadata trail. Using metadata, armored data is read from the ciphertrail whose keys and initialization vectors are got with Argon2 from the 32 byte key. Part of armored data might be lost, and data loss is tracked through the Hamming code and Reed-Solomon codes and erroneous codes are replaced with 0s where necessary as per those algorithms. After data is unarmored, it is also decompressed from gzip and output either to the named file or to stdout.

Miscellannious
--------------

Stego.jar uses BackBlaze JavaReedSolomon-master.jar and Bouncy Castle bcprov-jdk18on-171.jar both of which have MIT licence. It also is in itself offered in MIT licence.


LICENCE
=======

Copyright 2022 syy

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.