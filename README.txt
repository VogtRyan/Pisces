PISCES: PASSWORD-BASED FILE ENCRYPTION
Version 5.2.4 (7 April 2025)

Ryan Vogt
rvogt.ca@gmail.com

Contents:
1. Copyright Notice
2. About Pisces
3. Installing Pisces
4. Example Pisces Usage
5. Example Pwgen Usage
6. Cryptographic Details
7. Historical Details
8. Additional Build Targets

-------------------------------------------------------------------------------

1. Copyright Notice

Copyright (c) 2008-2025 Ryan Vogt <rvogt.ca@gmail.com>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-------------------------------------------------------------------------------

2. About Pisces

Pisces is an open-source, password-based encryption program for Unix (macOS,
Linux, OpenBSD, etc.). There are three key goals that Pisces meets:

(1) Providing a simple command-line interface for encrypting and decrypting
    files using password-based encryption;
(2) Ensuring data integrity of encrypted files upon decryption (i.e., Pisces
    recognizes whether an encrypted file has been modified); and,
(3) Quickly determining (i.e., without attempting to decrypt the entire file)
    whether an incorrect password has been given to decrypt an encrypted file.

Pisces also includes Pwgen, a command-line utility for generating
cryptographically secure, unbiased random passwords.

Pisces is designed to work out of the box, with no dependencies other than
basic C compiler tools.

-------------------------------------------------------------------------------

3. Installing Pisces

To install Pisces on most systems, run:

    $ make
    $ sudo make install

    [or: doas make install]

To install Pisces on systems without arc4random_buf() support, use /dev/random
as the cryptographic pseudorandom number generator (CPRNG) instead:

    $ make CPRNG=dev
    $ sudo make install

Two binaries, pisces and pwgen (a password generator for Pisces), will be
installed in /usr/local/bin/. The two corresponding man pages will be installed
in /usr/local/man/man1/. 

The installation location can be modified by setting the PREFIX variable during
the "make install" build step:

    $ make
    $ make PREFIX=~/pisces install

That will install the binaries in ~/pisces/bin/ and the man pages in
~/pisces/man/man1/.

To uninstall Pisces, delete the two binaries (pisces, pwgen) and their two man
pages (pisces.1, pwgen.1).

-------------------------------------------------------------------------------

4. Example Pisces Usage

To encrypt the contents of an input file, foo.txt, to an output file, foo.enc:

    $ pisces foo.txt foo.enc

To decrypt the contents of the file foo.enc, with a command-line argument as
the password, and store the original unencrypted data in a new file, foo.orig:

    $ pisces -d -p 'secret' foo.enc foo.orig

To decrypt a file to standard output and filter the contents using grep:

    $ pisces -d -o foo.enc | grep bar

To encrypt a file from standard input, piped from cat:

    $ cat foo.txt | pisces -i foo.enc

To verify that a file would decrypt and pass Pisces' file-integrity check,
without writing the decrypted file to disk:

    $ pisces -d foo.enc /dev/null

To archive and encrypt a directory, foodir/, with the GNU version of tar
(installed as gtar in the example) performing the archiving operation:

    $ gtar czf - foodir/ --format=posix | pisces -i foodir.enc

To restore an archived, encrypted directory to a new directory, newfoo/:

    $ mkdir newfoo/
    $ pisces -d -o foodir.enc | gtar xzf - --strip-components=1 -C newfoo/

See the pisces.1 man page for more details.

-------------------------------------------------------------------------------

5. Example Pwgen Usage

To generate a 24-character password guaranteed to contain at least one
uppercase letter, one lowercase letter, one number, and one special character:

    $ pwgen

To generate a four-digit PIN:

    $ pwgen -l 4 -p

To generate a 12-character hexadecimal string:

    $ pwgen -l 12 -h

To generate a 22-character alphanumeric password using uppercase letters,
lowercase letters, and numbers, without guaranteeing the presence of each type:

    $ pwgen -l 22 -n

To describe how many bits of security are provided by the 22-character
alphanumeric password generated above:

    $ pwgen -l 22 -n -d

See the pwgen.1 man page for more details.

-------------------------------------------------------------------------------

6. Cryptographic Details

When Pisces is used to encrypt a file, the user enters a one-line password (or
passphrase) that will later be used to decrypt the file. That password is
transformed into an encryption key, K, using a key derivation function, KDF.
KDF will salt the password using a randomly generated salt, S, with length
equal to the length of the key K.

The first element placed into the output file is a header. The header begins
with the six characters PISCES, followed by a one-byte encoding of the file
format version. The current version of Pisces uses the Pisces version 5
specifications, so the single byte 0x05 will be output. The next component in
the header is the salt, S. That will be followed by two randomly generated
initialization vectors, denoted I and J.

Following the header, an imprint is placed into the output file. When Pisces is
used to decrypt the file, and a user enters password P' which gets transformed
using the stored salt S into a key K', the imprint makes it possible to check
quickly whether K' was the key used to encrypt that file. However, given the
imprint, it is not feasible to compute the key K that was used in the original
encryption. Specifically, some random data R is generated. Then, a
cryptographic hash of R is computed, H(R), and these data are concatenated:
R || H(R). The imprint is an encrypted version of this concatenation using the
key K and the initialization vector I: E[K, I](R || H(R)).

For the imprint, the size of R is chosen such that it is at least as large as 
the output of H, and at least as large as both the block size and key size of 
E. Furthermore, the size of R is chosen such that the length of R plus the 
length of the output of H is a multiple of the block size of E.  Because of
this size choice, no padding is used during the encryption operation for the 
imprint.

Next, the key K and the second initialization vector, J, are used as
parameters to the encryption algorithm E to encrypt the contents of
the input file. If C represents the contents of the input file, then
E[K, J](C || H(C)) is output to the output file. Because the length of C is
indeterminate, PKCS #7 padding is used this time in E.

In Pisces version 5,

- E is 256-bit AES in CBC mode;
- H is SHA3-512; and,
- KDF is PBKDF2, using HMAC-SHA3-512 as the generator, with 16384 iterations.

Because of these choices, R is 512 bits in length; I and J are 128 bits in
length; and, S is 256 bits in length.

-------------------------------------------------------------------------------

7. Historical Details

The current version of Pisces is Pisces 5, as specified above.

Pisces 1 and Pisces 2 were internal development versions, and files encrypted
in either of those formats simply do not exist anymore. Version 1 used the
Twofish block cipher, giving the Pisces project its name. The name stuck, even
though the underlying block cipher changed.

While the current version of Pisces will only produce version 5 encrypted
files, it is still able to decrypt files produced by every version of Pisces
that has been publicly released, specifically versions 3, 4, and 5.

In Pisces version 4,

- E was 256-bit AES in CBC mode;
- H was SHA1;
- KDF was PBKDF2, using HMAC-SHA1 as the generator, with 4096 iterations;
- R was 352 bits in length; I and J were 128 bits in length; and, S was 256
  bits in length.

In Pisces version 3,

- E was 128-bit AES in CBC mode;
- H was SHA1; and,
- KDF was PBKDF2, using HMAC-SHA1 as the generator, with 1024 iterations;
- R was 224 bits in length; and, I, J, and S were all 128 bits in length.

-------------------------------------------------------------------------------

8. Additional Build Targets

Some of the code in aes_ecb.c and sha3.c has been algorithmically generated. To
build the code that generates the code in those two files, run:

    $ make generate

To generate the AES and SHA3 code, run:

    $ ./bin/generate_aes
    $ ./bin/generate_sha3

Additionally, there are a series of tests to ensure that Pisces' AES-ECB,
AES-CBC, SHA1, SHA3, HMAC, and PBKDF2 implementations are running correctly.
They are run automatically by the default make target, but can be run
explicitly using:

    $ make test

Any build target can be built in strict mode, to make the compiler treat all
warnings as errors, by setting the BUILD variable to strict:

    $ make BUILD=strict clean all

Finally, any build target can be built in debug mode, to contain symbols for a
C debugger and to produce more verbose output, by setting the BUILD variable to
debug:

    $ make BUILD=debug clean all

When a make target is built with BUILD set to debug, a failed test in the
cryptographic test suite will not cause the build to abort.
