Stego
=====

Stego is a tool and library for steganographic hiding of data into large random files.

An empty bitfile named dataplate of 10^9 bytes is created with command:
java -jar stego.jar dataplate.1 -c 1G

File payload.txt is written into bitfile dataplate with command:
java -jar stego.jar dataplate.2 -i dataplate.1 -w payload.txt

File payload.txt is read to stdout from bitfile dataplate with command:
java -jar stego.jar dataplate.2 -r -payload.txt


Concepts
--------

BITFILE is a large file filled with cryptographically secure random data that is opened and closed to a password

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

Technical details
-----------------

Bitfile consists two bitfields, inner and outer. Outer bitfield contains first the key for inner bitfield, 32 bytes, encrypted with the password and random tailing, at its start. After that there is, in clear, salt for the inner bitfield. After those two entries is the inner bitfield, encrypted with the content cipher on the mentioned key. Inner bitfield starts with salt, and the rest of the field is the data area.

+==== ENCRYPTED METADATA
|0-47B: encrypted metadata label, which is (0-7B runway, 8-39B key, 40-47B size of data area
+==== PLAIN SALT for metadata
|48-79B: outer bitfield salt
+==== ENCRYPTED INNER BITFIELD, SALT
|80-111B: inner bitfield salt for any stegofiles inside
+==== ENCRYPTED DATA AREA containing randomness and stegodata
| ++

The data area is encrypted at rest to make it harder to grap clear copies of the data area. If adversary gets copies of cleartext data area of same bitfile before and after insertion of stego contents, they can check how they differ and estimate a maximum possible change inserted before the snapshots.

Stegofile is written to the data area with its content bits encrypted with content cipher of AES 256 using a random initialization vector and a block counter. The addresses of each encrypted bit is decided by address cipher, which generates 64 bit addresses with another initialization vector and key and a block counter. The both keys and initialization vectors are got by combining the following:

+====
|0-31B: bitfile salt
+====
|32-63B: stegofile key
+====

 =>

+====
|0-31B: address key for AES 256
+====
|32-55B: address initialization vector
+====
|56-87B: content key for AES 256
+====
|88-111B: content initialization vector
+====

Cleardata for writing a stegofile is read from disk, then put through gzip, that result is armored first by Reed-Solomon encoding, its result is then encoded with Hamming(7,4) encoding to protect against data rot. The final result is encrypted and diversified with the method described earlier.

The stegofile key and the amount of data after compression but before armor encoding is recorded to a metadata label which also contains at its start a runway of 8 bytes with all-1 bits in order to confirm detection of true metadata label. This metadata label is stegowritten to address that is determined by the infile salt, the name of the cleardata file and random amount of tailing bytes.

+====
|0-31B: bitfile salt
+====
|32+B filename in UTF-8
+====
|X+B random tailing bytes, chosen by counting how many 1s come from a SecureRandom and dividing the result by integer 4 and adding 1 to result.
|   The point of random amount selection is to make it unprovable that a given name key does not exist in the bitfile.
+====

 =>

+====
|0-7B: all-1s, that is constant value 255
+====
|8-39B: 32 byte random key for the actual stegodata
+====
|40-47B: length of unarmored stegodata
+====

Changes to inner bitfile are written so that first a piece of bitfile is read from disk, decrypted with bitfile key into memory, then stegodata that comes to that part of bitfile are written on it, and then the data slice is encrypted to the new bitfile with the new bitfile's key and outer filesalt.

Miscellannious
--------------

Stego.jar uses BackBlaze JavaReedSolomon-master.jar and Bouncy Castle bcprov-jdk18on-171.jar both of which have MIT licence. It also is in itself offered in MIT licence.


LICENCE
=======

Copyright 2022 syy

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.