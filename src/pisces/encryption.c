/*
 * Copyright (c) 2008-2023 Ryan Vogt <rvogt.ca@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "encryption.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/chf.h"
#include "crypto/abstract/cipher.h"
#include "crypto/abstract/cprng.h"
#include "crypto/abstract/kdf.h"
#include "pisces/holdbuf.h"
#include "pisces/iowrap.h"
#include "pisces/version.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

/*
 * Decryption error message, in the case of the imprint check failing
 */
#define CANNOT_DECRYPT                                                        \
    "Cannot decrypt input file.  Either:\n"                                   \
    "- The file was not encrypted in Pisces format; or,\n"                    \
    "- A different key was used to encrypt the file."

/*
 * Bytes to read from input file on each read
 */
#define BYTES_AT_ONCE (4096)

/*
 * The Pisces header: these 6 bytes, followed by a one-byte version number. The
 * version number is not included in the length.
 */
#define PISCES_HEADER "PISCES"
#define PISCES_HEADER_LEN (6)

/*
 * PISCES_MAX_RANDOM_SIZE defines an upper bound on the amount of random data
 * used as part of the imprint.
 *
 * The amount of random data is guaranteed to be as large as:
 *   - The size of the hash output
 *   - The cipher block size
 *   - The cipher key size
 *
 * Additionally, the length of the random data plus the length of a hash output
 * is a multiple of the block size (so the imprint can be encrypted without
 * padding). Hence, the amount of random data is no larger than the largest of
 * the three items above, plus the block size minus one (the most "extra"
 * random data that would have to be added to make the random data plus the
 * hash a multiple of the block size).
 */
#if CHF_MAX_DIGEST_BYTES > CIPHER_MAX_BLOCK_BYTES
#if CHF_MAX_DIGEST_BYTES > CIPHER_MAX_KEY_BYTES
#define BIGGEST_OF_THREE (CHF_MAX_DIGEST_BYTES)
#else
#define BIGGEST_OF_THREE (CIPHER_MAX_KEY_BYTES)
#endif
#else
#if CIPHER_MAX_BLOCK_BYTES > CIPHER_MAX_KEY_BYTES
#define BIGGEST_OF_THREE (CIPHER_MAX_BLOCK_BYTES)
#else
#define BIGGEST_OF_THREE (CIPHER_MAX_KEY_BYTES)
#endif
#endif
#define PISCES_MAX_RANDOM_SIZE (BIGGEST_OF_THREE + CIPHER_MAX_BLOCK_BYTES - 1)

/*
 * An upper bound on the size of the imprint.  The imprint is the random data
 * size plus the size of its hash. The size of the imprint is guaranteed
 * to be the same encrypted and unencrypted.
 */
#define PISCES_MAX_IMPRINT_SIZE (PISCES_MAX_RANDOM_SIZE + CHF_MAX_DIGEST_BYTES)

/*
 * Generates the salt and two IVs and stores them into the provided arrays
 * Writes out the Pisces identification header, followed by the salt and IVs.
 * This function relies on the Pisces version already having been set, as it
 * uses pisces_get_version(). Returns 0 on success, -1 on error (and prints
 * error messages).
 */
static int write_header(int fd, byte_t *salt, byte_t *imprintIV,
                        byte_t *bodyIV);

/*
 * Reads in the Pisces identification header, sets the version of Pisces being
 * used to match the version in the file, then reads the salt and two IVs.
 * Returns 0 on success, -1 on error (and prints error messages).
 */
static int read_header(int fd, byte_t *salt, byte_t *imprintIV,
                       byte_t *bodyIV);

/*
 * Writes the key-verification imprint to the file, using the provided key and
 * imprint IV. Returns 0 on success, -1 on error (and prints error messages).
 */
static int write_imprint(int fd, const byte_t *key, const byte_t *imprintIV);

/*
 * Reads the key-verification imprint from the file, and verifies that the
 * correct key is being used to decrypt this file, by running computations with
 * the provided key and IV. Returns 0 on success, -1 on error (and prints error
 * messages).
 */
static int read_imprint(int fd, const byte_t *key, const byte_t *imprintIV);

/*
 * Encrypts the input contents to the output file descriptor, using the
 * provided key and IV. Returns 0 on success, -1 on error (and prints error
 * messages).
 */
static int encrypt_body(int in, int out, const byte_t *key,
                        const byte_t *bodyIV);

/*
 * Decrypts the input contents to the output file descriptor, using the
 * provided key and IV. Returns 0 on success, -1 on error (and prints error
 * messages).
 */
static int decrypt_body(int in, int out, const byte_t *key,
                        const byte_t *bodyIV);

/*
 * Converts the given password and salt into a key to be used with a
 * cryptographic primitive.
 */
static int password_to_key(byte_t *derivedKey, const char *password,
                           size_t passwordLen, const byte_t *salt);

/*
 * Computes both the total size of the key-verification imprint, as well as the
 * amount of random data in the imprint. Stores the results to the respective
 * variables.
 */
static void compute_imprint_sizes(size_t *randomData, size_t *total,
                                  const struct cipher_ctx *cipher,
                                  const struct chf_ctx *chf);

/*
 * Rounds the given number of bytes up to a multiple of the block size of the
 * given cipher. That is, it adds between 0 and blockSize(cipher)-1 bytes to
 * the given size. It is a fatal error for an overflow to occur.
 */
size_t cipher_block_ceiling(size_t bytes, const struct cipher_ctx *cipher);

int encrypt_file(const char *inputFile, const char *outputFile,
                 const char *password, size_t passwordLen)
{
    byte_t key[CIPHER_MAX_KEY_BYTES];
    byte_t salt[CIPHER_MAX_KEY_BYTES];
    byte_t imprintIV[CIPHER_MAX_BLOCK_BYTES];
    byte_t bodyIV[CIPHER_MAX_BLOCK_BYTES];
    int in = -1;
    int out = -1;
    int errVal = 0;

    /* Open the input and output files */
    in = open_input_file(inputFile);
    if (in == -1) {
        ERROR(isErr, errVal, "Could not open input file: %s",
              (inputFile == NULL ? "standard input" : inputFile));
    }
    out = open_output_file(outputFile);
    if (out == -1) {
        ERROR(isErr, errVal, "Could not open output file: %s",
              (outputFile == NULL ? "standard output" : outputFile));
    }

    /* Generate and write the salt+IVs into the header, and derive our key. */
    if (write_header(out, salt, imprintIV, bodyIV)) {
        ERROR_QUIET(isErr, errVal);
    }
    if (password_to_key(key, password, passwordLen, salt)) {
        ERROR_QUIET(isErr, errVal);
    }

    /* Write the imprint, then encrypt the file */
    if (write_imprint(out, key, imprintIV)) {
        ERROR_QUIET(isErr, errVal);
    }
    if (encrypt_body(in, out, key, bodyIV)) {
        ERROR_QUIET(isErr, errVal);
    }

isErr:
    if (in != -1) {
        close(in);
    }
    if (out != -1) {
        close(out);
    }
    scrub_memory(key, CIPHER_MAX_KEY_BYTES);
    return errVal ? -1 : 0;
}

int decrypt_file(const char *inputFile, const char *outputFile,
                 const char *password, size_t passwordLen)
{
    byte_t key[CIPHER_MAX_KEY_BYTES];
    byte_t salt[CIPHER_MAX_KEY_BYTES];
    byte_t imprintIV[CIPHER_MAX_BLOCK_BYTES];
    byte_t bodyIV[CIPHER_MAX_BLOCK_BYTES];
    int in = -1;
    int out = -1;
    int errVal = 0;

    /* Open the input file */
    in = open_input_file(inputFile);
    if (in == -1) {
        ERROR(isErr, errVal, "Could not open input file: %s",
              (inputFile == NULL ? "standard input" : inputFile));
    }

    /*
     * Read the header to determine the version, then get the salt and IVs to
     * derive the key from the password
     */
    if (read_header(in, salt, imprintIV, bodyIV)) {
        ERROR_QUIET(isErr, errVal);
    }
    if (password_to_key(key, password, passwordLen, salt)) {
        ERROR_QUIET(isErr, errVal);
    }

    /* Verify the imprint before opening the output file */
    if (read_imprint(in, key, imprintIV)) {
        ERROR_QUIET(isErr, errVal);
    }

    /* Now open the output file and decrypt the body */
    out = open_output_file(outputFile);
    if (out == -1) {
        ERROR(isErr, errVal, "Could not open output file: %s",
              (outputFile == NULL ? "standard output" : outputFile));
    }
    if (decrypt_body(in, out, key, bodyIV)) {
        ERROR_QUIET(isErr, errVal);
    }

isErr:
    if (in != -1) {
        close(in);
    }
    if (out != -1) {
        close(out);
    }
    scrub_memory(key, CIPHER_MAX_KEY_BYTES);
    return errVal ? -1 : 0;
}

static int write_header(int fd, byte_t *salt, byte_t *imprintIV,
                        byte_t *bodyIV)
{
    struct cipher_ctx *cipher = NULL;
    struct cprng *rng = NULL;
    byte_t versionByte;
    size_t keyAndSaltLen, ivLen;
    int errVal = 0;

    /* Write the magic Pisces identifier and the version number */
    versionByte = (byte_t)pisces_get_version();
    if (write_exactly(fd, (byte_t *)PISCES_HEADER, PISCES_HEADER_LEN)) {
        ERROR(isErr, errVal, "Could not write header to output");
    }
    if (write_exactly(fd, &versionByte, 1)) {
        ERROR(isErr, errVal, "Could not write version byte");
    }

    /* Generate the random salt and IVs */
    cipher = pisces_unpadded_cipher_alloc();
    rng = cprng_alloc_default();
    keyAndSaltLen = cipher_key_size(cipher);
    ivLen = cipher_iv_size(cipher);
    cprng_bytes(rng, salt, keyAndSaltLen);
    cprng_bytes(rng, imprintIV, ivLen);
    cprng_bytes(rng, bodyIV, ivLen);

    /* Write out the salt and IVs */
    if (write_exactly(fd, salt, keyAndSaltLen)) {
        ERROR(isErr, errVal, "Could not write salt");
    }
    if (write_exactly(fd, imprintIV, ivLen)) {
        ERROR(isErr, errVal, "Could not write imprint IV");
    }
    if (write_exactly(fd, bodyIV, ivLen)) {
        ERROR(isErr, errVal, "Could not write body IV");
    }

isErr:
    cipher_free_scrub(cipher);
    cprng_free_scrub(rng);
    return errVal ? -1 : 0;
}

static int read_header(int fd, byte_t *salt, byte_t *imprintIV, byte_t *bodyIV)
{
    struct cipher_ctx *cipher = NULL;
    byte_t header[PISCES_HEADER_LEN];
    byte_t versionByte;
    size_t keyAndSaltLen, ivLen;
    int errVal = 0;

    /* Read the magic Pisces identifier and the version number */
    if (read_exactly(fd, header, PISCES_HEADER_LEN)) {
        ERROR(isErr, errVal, "Could not read Pisces header from input");
    }
    if (memcmp(header, PISCES_HEADER, PISCES_HEADER_LEN) != 0) {
        ERROR(isErr, errVal, CANNOT_DECRYPT);
    }
    if (read_exactly(fd, &versionByte, 1)) {
        ERROR(isErr, errVal, "Could not read Pisces version from input");
    }
    if (pisces_set_version((int)versionByte)) {
        ERROR(isErr, errVal, "Unsupported Pisces version: %d",
              (int)versionByte);
    }

    /* Get the cipher primitive */
    cipher = pisces_unpadded_cipher_alloc();

    /* Read the random salt and IVs */
    keyAndSaltLen = cipher_key_size(cipher);
    ivLen = cipher_iv_size(cipher);
    if (read_exactly(fd, salt, keyAndSaltLen)) {
        ERROR(isErr, errVal, "Could not read salt");
    }
    if (read_exactly(fd, imprintIV, ivLen)) {
        ERROR(isErr, errVal, "Could not read imprint IV");
    }
    if (read_exactly(fd, bodyIV, ivLen)) {
        ERROR(isErr, errVal, "Could not read body IV");
    }

isErr:
    cipher_free_scrub(cipher);
    return errVal ? -1 : 0;
}

static int write_imprint(int fd, const byte_t *key, const byte_t *imprintIV)
{
    struct chf_ctx *chf = NULL;
    struct cipher_ctx *cipher = NULL;
    struct cprng *rng = NULL;
    byte_t randomData[PISCES_MAX_RANDOM_SIZE];
    byte_t randomHash[CHF_MAX_DIGEST_BYTES];
    byte_t encryptedImprint[PISCES_MAX_IMPRINT_SIZE];
    size_t randomLen, hashLen, totalLen;
    size_t encOutA, encOutB;
    int errVal = 0;

    /* Generate the random data */
    chf = pisces_chf_alloc();
    cipher = pisces_unpadded_cipher_alloc();
    rng = cprng_alloc_default();
    hashLen = chf_digest_size(chf);
    compute_imprint_sizes(&randomLen, &totalLen, cipher, chf);
    cprng_bytes(rng, randomData, randomLen);

    /* Hash the random data */
    if (chf_single(chf, randomData, randomLen, randomHash)) {
        ERROR(isErr, errVal, "Could not hash random imprint data - %s",
              chf_error(chf));
    }

    /* Encrypt the random data and the hash without padding */
    cipher_set_direction(cipher, CIPHER_DIRECTION_ENCRYPT);
    cipher_set_iv(cipher, imprintIV);
    cipher_set_key(cipher, key);
    cipher_start(cipher);
    cipher_add(cipher, randomData, randomLen, encryptedImprint, &encOutA);
    cipher_add(cipher, randomHash, hashLen, encryptedImprint + encOutA,
               &encOutB);
    if (cipher_end(cipher, encryptedImprint + encOutA + encOutB, NULL)) {
        ERROR(isErr, errVal, "Could not encrypt imprint data - %s",
              cipher_error(cipher));
    }

    /* Write out the encrypted imprint */
    if (write_exactly(fd, encryptedImprint, totalLen)) {
        ERROR(isErr, errVal, "Could not write encrypted imprint");
    }

isErr:
    chf_free_scrub(chf);
    cipher_free_scrub(cipher);
    cprng_free_scrub(rng);
    scrub_memory(randomData, PISCES_MAX_RANDOM_SIZE);
    scrub_memory(randomHash, CHF_MAX_DIGEST_BYTES);
    return errVal ? -1 : 0;
}

static int read_imprint(int fd, const byte_t *key, const byte_t *imprintIV)
{
    struct chf_ctx *chf = NULL;
    struct cipher_ctx *cipher = NULL;
    byte_t encryptedImprint[PISCES_MAX_IMPRINT_SIZE];
    byte_t decryptedImprint[PISCES_MAX_IMPRINT_SIZE];
    byte_t computedHash[CHF_MAX_DIGEST_BYTES];
    size_t randomLen, hashLen, totalLen;
    size_t decOut;
    int errVal = 0;

    /* Compute the necessary sizes */
    chf = pisces_chf_alloc();
    cipher = pisces_unpadded_cipher_alloc();
    hashLen = chf_digest_size(chf);
    compute_imprint_sizes(&randomLen, &totalLen, cipher, chf);

    /* Read the encrypted imprint and decrypt it */
    if (read_exactly(fd, encryptedImprint, totalLen)) {
        ERROR(isErr, errVal, "Could not read encrypted imprint");
    }
    cipher_set_direction(cipher, CIPHER_DIRECTION_DECRYPT);
    cipher_set_iv(cipher, imprintIV);
    cipher_set_key(cipher, key);
    cipher_start(cipher);
    cipher_add(cipher, encryptedImprint, totalLen, decryptedImprint, &decOut);
    if (cipher_end(cipher, decryptedImprint + decOut, NULL)) {
        ERROR(isErr, errVal, "Could not decrypt imprint data - %s",
              cipher_error(cipher));
    }

    /* Compute the hash of the random data portion of the decrypted data */
    if (chf_single(chf, decryptedImprint, randomLen, computedHash)) {
        ERROR(isErr, errVal,
              "Could not compute hash of decrypted imprint - %s",
              chf_error(chf));
    }

    /* Compare the two hashes */
    if (memcmp(computedHash, decryptedImprint + randomLen, hashLen) != 0) {
        ERROR(isErr, errVal, CANNOT_DECRYPT);
    }

isErr:
    chf_free_scrub(chf);
    cipher_free_scrub(cipher);
    scrub_memory(decryptedImprint, PISCES_MAX_IMPRINT_SIZE);
    scrub_memory(computedHash, CHF_MAX_DIGEST_BYTES);
    return errVal ? -1 : 0;
}

static int encrypt_body(int in, int out, const byte_t *key,
                        const byte_t *bodyIV)
{
    struct chf_ctx *chf = NULL;
    struct cipher_ctx *cipher = NULL;
    byte_t buffer[BYTES_AT_ONCE];
    byte_t hash[CHF_MAX_DIGEST_BYTES];
    byte_t eBuf[BYTES_AT_ONCE + CHF_MAX_DIGEST_BYTES + CIPHER_MAX_BLOCK_BYTES];
    size_t hashLen, bytesRead, bytesEnc;
    int errVal = 0;

    /* Initialize the message digest */
    chf = pisces_chf_alloc();
    hashLen = chf_digest_size(chf);
    chf_start(chf);

    /* Initialize the cipher */
    cipher = pisces_padded_cipher_alloc();
    cipher_set_direction(cipher, CIPHER_DIRECTION_ENCRYPT);
    cipher_set_iv(cipher, bodyIV);
    cipher_set_key(cipher, key);
    cipher_start(cipher);

    /* Loop until all data is encrypted */
    while (1) {
        /* Read up to BYTES_AT_ONCE from the input source */
        if (read_up_to(in, buffer, BYTES_AT_ONCE, &bytesRead)) {
            ERROR(isErr, errVal, "Could not read bytes to encrypt from input");
        }
        if (bytesRead == 0) {
            break;
        }

        /* Cipher and hash the data, then write out the ciphered data */
        cipher_add(cipher, buffer, bytesRead, eBuf, &bytesEnc);
        if (chf_add(chf, buffer, bytesRead)) {
            ERROR(isErr, errVal,
                  "Could not generate hash of input contents - %s",
                  chf_error(chf));
        }
        if (write_exactly(out, eBuf, bytesEnc)) {
            ERROR(isErr, errVal, "Could not write encrypted data to output");
        }
    }

    /* Finalize and encrypt the hash */
    if (chf_end(chf, hash)) {
        ERROR(isErr, errVal, "Could not generate hash of input contents - %s",
              chf_error(chf));
    }
    cipher_add(cipher, hash, hashLen, eBuf, &bytesEnc);
    if (write_exactly(out, eBuf, bytesEnc)) {
        ERROR(isErr, errVal, "Could not write encrypted data to output");
    }

    /* Write out the final padded block */
    if (cipher_end(cipher, eBuf, &bytesEnc)) {
        ERROR(isErr, errVal, "Could not encrypt input contents - %s",
              cipher_error(cipher));
    }
    if (write_exactly(out, eBuf, bytesEnc)) {
        ERROR(isErr, errVal, "Could not write encrypted data to output");
    }

isErr:
    chf_free_scrub(chf);
    cipher_free_scrub(cipher);
    scrub_memory(buffer, BYTES_AT_ONCE);
    scrub_memory(hash, CHF_MAX_DIGEST_BYTES);
    return errVal ? -1 : 0;
}

static int decrypt_body(int in, int out, const byte_t *key,
                        const byte_t *bodyIV)
{
    struct chf_ctx *chf = NULL;
    struct cipher_ctx *cipher = NULL;
    struct holdbuf *hb = NULL;
    byte_t buffer[BYTES_AT_ONCE];
    byte_t dBuf[BYTES_AT_ONCE + CIPHER_MAX_BLOCK_BYTES];
    byte_t retFromHB[BYTES_AT_ONCE + CIPHER_MAX_BLOCK_BYTES];
    byte_t storedHash[CHF_MAX_DIGEST_BYTES];
    byte_t computedHash[CHF_MAX_DIGEST_BYTES];
    size_t hashLen, bytesRead, bytesDec, bytesReturned;
    int errVal = 0;

    /* Initialize the cipher, message digest, and holdback buffer */
    chf = pisces_chf_alloc();
    chf_start(chf);
    hashLen = chf_digest_size(chf);

    cipher = pisces_padded_cipher_alloc();
    cipher_set_direction(cipher, CIPHER_DIRECTION_DECRYPT);
    cipher_set_iv(cipher, bodyIV);
    cipher_set_key(cipher, key);
    cipher_start(cipher);

    hb = holdbuf_alloc(hashLen);

    /* Loop until all data is decrypted */
    while (1) {
        /* Read up to BYTES_AT_ONCE from the input source */
        if (read_up_to(in, buffer, BYTES_AT_ONCE, &bytesRead)) {
            ERROR(isErr, errVal, "Could not read bytes to decrypt from input");
        }
        if (bytesRead == 0) {
            break;
        }

        /*
         * Decrypt the data, then write and hash what the holdback buffer
         * allows
         */
        cipher_add(cipher, buffer, bytesRead, dBuf, &bytesDec);
        holdbuf_give(hb, dBuf, bytesDec, retFromHB, &bytesReturned);
        if (chf_add(chf, retFromHB, bytesReturned)) {
            ERROR(isErr, errVal,
                  "Could not compute hash for decrypted data - %s",
                  chf_error(chf));
        }
        if (write_exactly(out, retFromHB, bytesReturned)) {
            ERROR(isErr, errVal, "Could not write decrypted data to output");
        }
    }

    /* Decrypt the final padded block into the holdback, then hash/write */
    if (cipher_end(cipher, dBuf, &bytesDec)) {
        ERROR(isErr, errVal, "Could not decrypt input contents - %s",
              cipher_error(cipher));
    }
    holdbuf_give(hb, dBuf, bytesDec, retFromHB, &bytesReturned);
    if (chf_add(chf, retFromHB, bytesReturned)) {
        ERROR(isErr, errVal, "Could not compute hash for decrypted data - %s",
              chf_error(chf));
    }
    if (write_exactly(out, retFromHB, bytesReturned)) {
        ERROR(isErr, errVal, "Could not write decrypted data to output");
    }

    /*
     * Grab the remaining hashLen bytes out of the holdback to verify the file
     */
    if (holdbuf_end(hb, storedHash)) {
        ERROR(isErr, errVal, "Could not get stored hash value from buffer");
    }
    if (chf_end(chf, computedHash)) {
        ERROR(isErr, errVal, "Could not compute hash for decrypted data - %s",
              chf_error(chf));
    }
    if (memcmp(storedHash, computedHash, hashLen) != 0) {
        ERROR(isErr, errVal, "Data integrity check failed on input file");
    }

isErr:
    chf_free_scrub(chf);
    cipher_free_scrub(cipher);
    holdbuf_free_scrub(hb);
    scrub_memory(dBuf, BYTES_AT_ONCE + CIPHER_MAX_BLOCK_BYTES);
    scrub_memory(retFromHB, BYTES_AT_ONCE + CIPHER_MAX_BLOCK_BYTES);
    scrub_memory(storedHash, CHF_MAX_DIGEST_BYTES);
    scrub_memory(computedHash, CHF_MAX_DIGEST_BYTES);
    return errVal ? -1 : 0;
}

static int password_to_key(byte_t *derivedKey, const char *password,
                           size_t passwordLen, const byte_t *salt)
{
    struct cipher_ctx *cipher = NULL;
    struct kdf *fn = NULL;
    size_t keyAndSaltLen;
    int errVal = 0;

    cipher = pisces_unpadded_cipher_alloc();
    fn = pisces_kdf_alloc();
    keyAndSaltLen = cipher_key_size(cipher);

    if (kdf_derive(fn, derivedKey, keyAndSaltLen, password, passwordLen, salt,
                   keyAndSaltLen)) {
        ERROR(isErr, errVal, "Could not derive key - %s", kdf_error(fn));
    }

isErr:
    cipher_free_scrub(cipher);
    kdf_free_scrub(fn);
    return errVal ? -1 : 0;
}

static void compute_imprint_sizes(size_t *randomData, size_t *total,
                                  const struct cipher_ctx *cipher,
                                  const struct chf_ctx *chf)
{
    size_t hashLen, blockLen, keyLen, max, required;

    /* Find which of the hash, block, and key lengths is the largest */
    hashLen = chf_digest_size(chf);
    blockLen = cipher_block_size(cipher);
    keyLen = cipher_key_size(cipher);
    max = hashLen > blockLen ? hashLen : blockLen;
    max = max > keyLen ? max : keyLen;

    /*
     * The total amount of data will be at least as large as that maximum,
     * plus the hash output.
     */
    required = max + hashLen;
    ASSERT(required >= max, "Addition overflow computing imprint size");
    *total = cipher_block_ceiling(required, cipher);
    *randomData = (*total) - hashLen;
}

size_t cipher_block_ceiling(size_t bytes, const struct cipher_ctx *cipher)
{
    size_t blockSize, remainder, res;

    blockSize = cipher_block_size(cipher);
    remainder = bytes % blockSize;
    if (remainder == 0) {
        return bytes;
    }
    else {
        res = bytes + (blockSize - remainder);
        ASSERT(res >= bytes, "Addition overflow computing block ceiling");
        return res;
    }
}
