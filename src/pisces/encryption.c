/*
 * Copyright (c) 2008-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#define INPUT_BYTES_READ_AT_ONCE (4096)

#define MESSAGE_CANNOT_DECRYPT                                                \
    "Cannot decrypt input file.  Either:\n"                                   \
    "- The file was not encrypted in Pisces format; or,\n"                    \
    "- A different key was used to encrypt the file."

/*
 * PISCES FILE FORMAT AND TERMINOLOGY
 *
 * Header:
 *     Magic bytes:
 *         6-byte magic prefix
 *         1-byte magic version number
 *     Salt
 *     Imprint IV
 *     Body IV
 * Imprint, encrypted with key K, imprint IV, no padding:
 *     Random data R
 *     Hash of the random data, H(R)
 * Body, encrypted with key K, body IV, padding:
 *     File contents C
 *     Hash of the file contents, H(C)
 */

#define PISCES_MAGIC_PREFIX     "PISCES"
#define PISCES_MAGIC_PREFIX_LEN (6)

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
 * is a multiple of the cipher's block size (so the imprint can be encrypted
 * without padding). Hence, the amount of random data is no larger than the
 * largest of the three items above, plus the block size minus one (the most
 * "extra" random data that would have to be added to make the random data
 * plus the hash a multiple of the block size).
 */
#if CHF_MAX_DIGEST_SIZE > CIPHER_MAX_BLOCK_SIZE
#if CHF_MAX_DIGEST_SIZE > CIPHER_MAX_KEY_SIZE
#define BIGGEST_OF_THREE (CHF_MAX_DIGEST_SIZE)
#else
#define BIGGEST_OF_THREE (CIPHER_MAX_KEY_SIZE)
#endif
#else
#if CIPHER_MAX_BLOCK_SIZE > CIPHER_MAX_KEY_SIZE
#define BIGGEST_OF_THREE (CIPHER_MAX_BLOCK_SIZE)
#else
#define BIGGEST_OF_THREE (CIPHER_MAX_KEY_SIZE)
#endif
#endif
#define PISCES_MAX_RANDOM_SIZE (BIGGEST_OF_THREE + CIPHER_MAX_BLOCK_SIZE - 1)

/*
 * An upper bound on the size of the imprint: the size of the random data, plus
 * the size of its hash. Because there is no padding in the imprint, the size
 * of the imprint is guaranteed to be the same encrypted and unencrypted.
 */
#define PISCES_MAX_IMPRINT_SIZE (PISCES_MAX_RANDOM_SIZE + CHF_MAX_DIGEST_SIZE)

#define MAX(a, b, c)                                                          \
    ((a) > (b) ? ((a) > (c) ? (a) : (c)) : ((b) > (c) ? (b) : (c)))

static int write_header(int fd, byte *salt, byte *imprint_iv, byte *body_iv);
static int read_header(int fd, byte *salt, byte *imprint_iv, byte *body_iv);

static int write_imprint(int fd, const byte *key, const byte *imprint_iv,
                         struct cprng *rng);
static int read_imprint(int fd, const byte *key, const byte *imprint_iv);

static int encrypt_body(int in, int out, const byte *key, const byte *body_iv);
static int decrypt_body(int in, int out, const byte *key, const byte *body_iv);

static void generate_salt_ivs(byte *salt, byte *iv1, byte *iv2,
                              struct cprng *rng);

static int password_to_key(byte *derived_key, const char *password,
                           size_t password_len, const byte *salt);

static void compute_imprint_size(size_t *random_data_size,
                                 size_t *total_imprint_size,
                                 const struct cipher_ctx *cipher,
                                 const struct chf_ctx *chf);
static size_t cipher_block_ceiling(size_t bytes,
                                   const struct cipher_ctx *cipher);

int encrypt_file(const char *input_file, const char *output_file,
                 const char *password, size_t password_len)
{
    struct cprng *rng = NULL;
    byte key[CIPHER_MAX_KEY_SIZE];
    byte salt[CIPHER_MAX_KEY_SIZE];
    byte imprint_iv[CIPHER_MAX_BLOCK_SIZE];
    byte body_iv[CIPHER_MAX_BLOCK_SIZE];
    int in = -1;
    int out = -1;
    int errval = 0;

    /* Catch any errors with the password before we start opening files */
    rng = cprng_alloc_default();
    generate_salt_ivs(salt, imprint_iv, body_iv, rng);
    if (password_to_key(key, password, password_len, salt)) {
        ERROR_QUIET(done, errval);
    }

    in = open_input_file(input_file);
    if (in == -1) {
        ERROR(done, errval, "Could not open input file: %s",
              (input_file == NULL ? "standard input" : input_file));
    }

    out = open_output_file(output_file);
    if (out == -1) {
        ERROR(done, errval, "Could not open output file: %s",
              (output_file == NULL ? "standard output" : output_file));
    }

    if (write_header(out, salt, imprint_iv, body_iv)) {
        ERROR_QUIET(done, errval);
    }
    if (write_imprint(out, key, imprint_iv, rng)) {
        ERROR_QUIET(done, errval);
    }
    if (encrypt_body(in, out, key, body_iv)) {
        ERROR_QUIET(done, errval);
    }

done:
    if (in != -1) {
        close(in);
    }
    if (out != -1) {
        close(out);
    }
    cprng_free_scrub(rng);
    scrub_memory(key, CIPHER_MAX_KEY_SIZE);
    return errval;
}

int decrypt_file(const char *input_file, const char *output_file,
                 const char *password, size_t password_len)
{
    byte key[CIPHER_MAX_KEY_SIZE];
    byte salt[CIPHER_MAX_KEY_SIZE];
    byte imprint_iv[CIPHER_MAX_BLOCK_SIZE];
    byte body_iv[CIPHER_MAX_BLOCK_SIZE];
    int in = -1;
    int out = -1;
    int errval = 0;

    in = open_input_file(input_file);
    if (in == -1) {
        ERROR(done, errval, "Could not open input file: %s",
              (input_file == NULL ? "standard input" : input_file));
    }

    if (read_header(in, salt, imprint_iv, body_iv)) {
        ERROR_QUIET(done, errval);
    }
    if (password_to_key(key, password, password_len, salt)) {
        ERROR_QUIET(done, errval);
    }
    if (read_imprint(in, key, imprint_iv)) {
        ERROR_QUIET(done, errval);
    }

    /*
     * Hold off on opening the output file until we've confirmed the decryption
     * key is correct.
     */
    out = open_output_file(output_file);
    if (out == -1) {
        ERROR(done, errval, "Could not open output file: %s",
              (output_file == NULL ? "standard output" : output_file));
    }

    if (decrypt_body(in, out, key, body_iv)) {
        ERROR_QUIET(done, errval);
    }

done:
    if (in != -1) {
        close(in);
    }
    if (out != -1) {
        close(out);
    }
    scrub_memory(key, CIPHER_MAX_KEY_SIZE);
    return errval;
}

static int write_header(int fd, byte *salt, byte *imprint_iv, byte *body_iv)
{
    struct cipher_ctx *cipher = NULL;
    byte magic_version;
    size_t key_salt_len, iv_len;
    int errval = 0;

    magic_version = (byte)pisces_get_version();
    if (write_exactly(fd, (byte *)PISCES_MAGIC_PREFIX,
                      PISCES_MAGIC_PREFIX_LEN)) {
        ERROR(done, errval, "Could not write magic-byte prefix");
    }
    if (write_exactly(fd, &magic_version, 1)) {
        ERROR(done, errval, "Could not write magic-byte version");
    }

    cipher = pisces_unpadded_cipher_alloc();
    key_salt_len = cipher_key_size(cipher);
    iv_len = cipher_iv_size(cipher);

    if (write_exactly(fd, salt, key_salt_len)) {
        ERROR(done, errval, "Could not write salt");
    }
    if (write_exactly(fd, imprint_iv, iv_len)) {
        ERROR(done, errval, "Could not write imprint IV");
    }
    if (write_exactly(fd, body_iv, iv_len)) {
        ERROR(done, errval, "Could not write body IV");
    }

done:
    cipher_free_scrub(cipher);
    return errval;
}

static int read_header(int fd, byte *salt, byte *imprint_iv, byte *body_iv)
{
    struct cipher_ctx *cipher = NULL;
    byte magic_prefix[PISCES_MAGIC_PREFIX_LEN];
    byte magic_version;
    size_t key_salt_len, iv_len;
    int errval = 0;

    if (read_exactly(fd, magic_prefix, PISCES_MAGIC_PREFIX_LEN)) {
        ERROR(done, errval, "Could not read magic-byte prefix");
    }
    if (memcmp(magic_prefix, PISCES_MAGIC_PREFIX, PISCES_MAGIC_PREFIX_LEN)) {
        ERROR(done, errval, MESSAGE_CANNOT_DECRYPT);
    }
    if (read_exactly(fd, &magic_version, 1)) {
        ERROR(done, errval, "Could not read magic-byte version");
    }
    if (pisces_set_version((int)magic_version)) {
        ERROR(done, errval, "Unsupported Pisces version: %d",
              (int)magic_version);
    }

    cipher = pisces_unpadded_cipher_alloc();
    key_salt_len = cipher_key_size(cipher);
    iv_len = cipher_iv_size(cipher);

    if (read_exactly(fd, salt, key_salt_len)) {
        ERROR(done, errval, "Could not read salt");
    }
    if (read_exactly(fd, imprint_iv, iv_len)) {
        ERROR(done, errval, "Could not read imprint IV");
    }
    if (read_exactly(fd, body_iv, iv_len)) {
        ERROR(done, errval, "Could not read body IV");
    }

done:
    cipher_free_scrub(cipher);
    return errval;
}

static int write_imprint(int fd, const byte *key, const byte *imprint_iv,
                         struct cprng *rng)
{
    struct chf_ctx *chf = NULL;
    struct cipher_ctx *cipher = NULL;
    byte random_data[PISCES_MAX_RANDOM_SIZE];
    byte random_hash[CHF_MAX_DIGEST_SIZE];
    byte encrypted_imprint[PISCES_MAX_IMPRINT_SIZE];
    size_t random_len, hash_len, total_len;
    size_t bytes_encrypted1, bytes_encrypted2;
    int errval = 0;

    chf = pisces_chf_alloc();
    cipher = pisces_unpadded_cipher_alloc();
    hash_len = chf_digest_size(chf);
    compute_imprint_size(&random_len, &total_len, cipher, chf);

    /*
     * The number of random bytes is small enough that we can generate them and
     * compute their hash all at once.
     */
    cprng_bytes(rng, random_data, random_len);
    if (chf_single(chf, random_data, random_len, random_hash)) {
        ERROR(done, errval, "Could not hash random imprint data - %s",
              chf_error(chf));
    }

    cipher_set_direction(cipher, CIPHER_DIRECTION_ENCRYPT);
    cipher_set_iv(cipher, imprint_iv);
    cipher_set_key(cipher, key);

    cipher_start(cipher);
    cipher_add(cipher, random_data, random_len, encrypted_imprint,
               &bytes_encrypted1);
    cipher_add(cipher, random_hash, hash_len,
               encrypted_imprint + bytes_encrypted1, &bytes_encrypted2);
    if (cipher_end(cipher,
                   encrypted_imprint + bytes_encrypted1 + bytes_encrypted2,
                   NULL)) {
        ERROR(done, errval, "Could not encrypt imprint data - %s",
              cipher_error(cipher));
    }

    if (write_exactly(fd, encrypted_imprint, total_len)) {
        ERROR(done, errval, "Could not write encrypted imprint");
    }

done:
    chf_free_scrub(chf);
    cipher_free_scrub(cipher);
    scrub_memory(random_data, PISCES_MAX_RANDOM_SIZE);
    scrub_memory(random_hash, CHF_MAX_DIGEST_SIZE);
    return errval;
}

static int read_imprint(int fd, const byte *key, const byte *imprint_iv)
{
    struct chf_ctx *chf = NULL;
    struct cipher_ctx *cipher = NULL;
    byte encrypted_imprint[PISCES_MAX_IMPRINT_SIZE];
    byte decrypted_imprint[PISCES_MAX_IMPRINT_SIZE];
    byte computed_hash[CHF_MAX_DIGEST_SIZE];
    size_t random_len, hash_len, total_len;
    size_t decrypted_len;
    int errval = 0;

    chf = pisces_chf_alloc();
    cipher = pisces_unpadded_cipher_alloc();
    hash_len = chf_digest_size(chf);
    compute_imprint_size(&random_len, &total_len, cipher, chf);

    /* Read the entire imprint */
    if (read_exactly(fd, encrypted_imprint, total_len)) {
        ERROR(done, errval, "Could not read encrypted imprint");
    }

    /*
     * Decrypt the entire imprint. We do not need the size filled in by
     * cipher_end(), because we know the size of the imprint the cipher context
     * will give us (if there is no error).
     */
    cipher_set_direction(cipher, CIPHER_DIRECTION_DECRYPT);
    cipher_set_iv(cipher, imprint_iv);
    cipher_set_key(cipher, key);
    cipher_start(cipher);
    cipher_add(cipher, encrypted_imprint, total_len, decrypted_imprint,
               &decrypted_len);
    if (cipher_end(cipher, decrypted_imprint + decrypted_len, NULL)) {
        ERROR(done, errval, "Could not decrypt imprint data - %s",
              cipher_error(cipher));
    }

    /* Hash only the first part of the decrypted imprint (the random data) */
    if (chf_single(chf, decrypted_imprint, random_len, computed_hash)) {
        ERROR(done, errval, "Could not compute hash of decrypted imprint - %s",
              chf_error(chf));
    }

    /*
     * Check the computed hash matches the decrypted hash found in the file. If
     * it does not, assume an incorrect decryption key was given.
     *
     * We ignore the possibility that there has been file corruption in the
     * imprint. That could render the hash in the imprint incorrect, despite
     * the body being intact. But, checking for that possibility at this point
     * (by decrypting the body and computing its hash) would defeat the purpose
     * of placing the imprint in the encrypted file.
     */
    if (memcmp(computed_hash, decrypted_imprint + random_len, hash_len) != 0) {
        ERROR(done, errval, MESSAGE_CANNOT_DECRYPT);
    }

done:
    chf_free_scrub(chf);
    cipher_free_scrub(cipher);
    scrub_memory(decrypted_imprint, PISCES_MAX_IMPRINT_SIZE);
    scrub_memory(computed_hash, CHF_MAX_DIGEST_SIZE);
    return errval;
}

static int encrypt_body(int in, int out, const byte *key, const byte *body_iv)
{
    struct chf_ctx *chf = NULL;
    struct cipher_ctx *cipher = NULL;
    byte input[INPUT_BYTES_READ_AT_ONCE];
    byte hash[CHF_MAX_DIGEST_SIZE];
    byte enc_data[INPUT_BYTES_READ_AT_ONCE + CHF_MAX_DIGEST_SIZE +
                  CIPHER_MAX_BLOCK_SIZE];
    size_t hash_len, bytes_read, bytes_encrypted;
    int errval = 0;

    chf = pisces_chf_alloc();
    hash_len = chf_digest_size(chf);
    chf_start(chf);

    cipher = pisces_padded_cipher_alloc();
    cipher_set_direction(cipher, CIPHER_DIRECTION_ENCRYPT);
    cipher_set_iv(cipher, body_iv);
    cipher_set_key(cipher, key);
    cipher_start(cipher);

    /*
     * Hash the all of the file contents, and write most (possibly all) of the
     * encrypted file contents out. It is possible (likely) that there are
     * still encrypted file contents in the cipher context at the end of this
     * loop, because of the padding scheme.
     */
    while (1) {
        if (read_up_to(in, input, INPUT_BYTES_READ_AT_ONCE, &bytes_read)) {
            ERROR(done, errval, "Could not read bytes to encrypt from input");
        }
        if (bytes_read == 0) {
            break;
        }

        if (chf_add(chf, input, bytes_read)) {
            ERROR(done, errval,
                  "Could not generate hash of input contents - %s",
                  chf_error(chf));
        }

        cipher_add(cipher, input, bytes_read, enc_data, &bytes_encrypted);
        if (write_exactly(out, enc_data, bytes_encrypted)) {
            ERROR(done, errval, "Could not write encrypted data to output");
        }
    }

    /*
     * All of the input file contents have been run through the hash context,
     * so the hash computation can be finalized.
     */
    if (chf_end(chf, hash)) {
        ERROR(done, errval, "Could not generate hash of input contents - %s",
              chf_error(chf));
    }

    /*
     * Adding the computed hash to the cipher context and finalizing the cipher
     * operation flushes any last encrypted file contents, along with the
     * encrypted hash of the file contents.
     */
    cipher_add(cipher, hash, hash_len, enc_data, &bytes_encrypted);
    if (write_exactly(out, enc_data, bytes_encrypted)) {
        ERROR(done, errval, "Could not write encrypted data to output");
    }
    if (cipher_end(cipher, enc_data, &bytes_encrypted)) {
        ERROR(done, errval, "Could not encrypt input contents - %s",
              cipher_error(cipher));
    }
    if (write_exactly(out, enc_data, bytes_encrypted)) {
        ERROR(done, errval, "Could not write encrypted data to output");
    }

done:
    chf_free_scrub(chf);
    cipher_free_scrub(cipher);
    scrub_memory(input, INPUT_BYTES_READ_AT_ONCE);
    scrub_memory(hash, CHF_MAX_DIGEST_SIZE);
    return errval;
}

static int decrypt_body(int in, int out, const byte *key, const byte *body_iv)
{
    struct chf_ctx *chf = NULL;
    struct cipher_ctx *cipher = NULL;
    struct holdbuf *hb = NULL;
    byte input[INPUT_BYTES_READ_AT_ONCE];
    byte dec_data[INPUT_BYTES_READ_AT_ONCE + CIPHER_MAX_BLOCK_SIZE];
    byte data_from_hb[INPUT_BYTES_READ_AT_ONCE + CIPHER_MAX_BLOCK_SIZE];
    byte stored_hash[CHF_MAX_DIGEST_SIZE];
    byte computed_hash[CHF_MAX_DIGEST_SIZE];
    size_t hash_len, bytes_read, bytes_decrypted, bytes_from_hb;
    int errval = 0;

    chf = pisces_chf_alloc();
    chf_start(chf);
    hash_len = chf_digest_size(chf);

    cipher = pisces_padded_cipher_alloc();
    cipher_set_direction(cipher, CIPHER_DIRECTION_DECRYPT);
    cipher_set_iv(cipher, body_iv);
    cipher_set_key(cipher, key);
    cipher_start(cipher);

    hb = holdbuf_alloc(hash_len);

    /*
     * We decrypt the entire body, but hash and write out only what the
     * holdback buffer allows. The final part of the decrypted input, retained
     * in the holdback buffer, is the supposed decrypted hash of the file
     * contents.
     */
    while (1) {
        if (read_up_to(in, input, INPUT_BYTES_READ_AT_ONCE, &bytes_read)) {
            ERROR(done, errval, "Could not read bytes to decrypt from input");
        }
        if (bytes_read == 0) {
            break;
        }

        cipher_add(cipher, input, bytes_read, dec_data, &bytes_decrypted);
        holdbuf_give(hb, dec_data, bytes_decrypted, data_from_hb,
                     &bytes_from_hb);

        if (chf_add(chf, data_from_hb, bytes_from_hb)) {
            ERROR(done, errval,
                  "Could not compute hash for decrypted data - %s",
                  chf_error(chf));
        }

        if (write_exactly(out, data_from_hb, bytes_from_hb)) {
            ERROR(done, errval, "Could not write decrypted data to output");
        }
    }

    /*
     * Everything the holdback buffer is giving back here is the last of the
     * file contents that have been decrypted.
     */
    if (cipher_end(cipher, dec_data, &bytes_decrypted)) {
        ERROR(done, errval, "Could not decrypt input contents - %s",
              cipher_error(cipher));
    }
    holdbuf_give(hb, dec_data, bytes_decrypted, data_from_hb, &bytes_from_hb);
    if (chf_add(chf, data_from_hb, bytes_from_hb)) {
        ERROR(done, errval, "Could not compute hash for decrypted data - %s",
              chf_error(chf));
    }
    if (write_exactly(out, data_from_hb, bytes_from_hb)) {
        ERROR(done, errval, "Could not write decrypted data to output");
    }

    /*
     * All that is left in the holdback buffer now is the supposed hash of the
     * file contents, as provided by the input file.
     */
    if (holdbuf_end(hb, stored_hash)) {
        ERROR(done, errval, "Could not get stored hash value from buffer");
    }
    if (chf_end(chf, computed_hash)) {
        ERROR(done, errval, "Could not compute hash for decrypted data - %s",
              chf_error(chf));
    }

    /*
     * If the hashes do not match, despite the hash check on the imprint
     * succeeding, we can safely conclude there was file corruption.
     */
    if (memcmp(stored_hash, computed_hash, hash_len) != 0) {
        ERROR(done, errval, "Data integrity check failed on input file");
    }

done:
    chf_free_scrub(chf);
    cipher_free_scrub(cipher);
    holdbuf_free_scrub(hb);
    scrub_memory(dec_data, INPUT_BYTES_READ_AT_ONCE + CIPHER_MAX_BLOCK_SIZE);
    scrub_memory(data_from_hb,
                 INPUT_BYTES_READ_AT_ONCE + CIPHER_MAX_BLOCK_SIZE);
    scrub_memory(stored_hash, CHF_MAX_DIGEST_SIZE);
    scrub_memory(computed_hash, CHF_MAX_DIGEST_SIZE);
    return errval;
}

static void generate_salt_ivs(byte *salt, byte *iv1, byte *iv2,
                              struct cprng *rng)
{
    struct cipher_ctx *cipher;
    size_t key_salt_len, iv_len;

    cipher = pisces_unpadded_cipher_alloc();
    key_salt_len = cipher_key_size(cipher);
    iv_len = cipher_iv_size(cipher);

    cprng_bytes(rng, salt, key_salt_len);

    /*
     * IVs cannot be reused for multiple cipher operations. That said, the
     * generated IVs being identical would be a coincidence so unlikely it
     * should realistically never happen (speaking in lifetime-of-the-universe
     * magnitude probabilities). If it happens, treat it as an error in the
     * cryptographic library. Use a fatal error (instead of aborting on a
     * failed assertion) to be consistent with the behaviour when we fail to
     * open a random number source from the system.
     */
    cprng_bytes(rng, iv1, iv_len);
    cprng_bytes(rng, iv2, iv_len);
    if (memcmp(iv1, iv2, iv_len) == 0) {
        FATAL_ERROR("Identical IVs generated");
    }

    cipher_free_scrub(cipher);
}

static int password_to_key(byte *derived_key, const char *password,
                           size_t password_len, const byte *salt)
{
    struct cipher_ctx *cipher = NULL;
    struct kdf *fn = NULL;
    size_t key_salt_len;
    int errval = 0;

    cipher = pisces_unpadded_cipher_alloc();
    fn = pisces_kdf_alloc();
    key_salt_len = cipher_key_size(cipher);

    if (kdf_derive(fn, derived_key, key_salt_len, password, password_len, salt,
                   key_salt_len)) {
        ERROR(done, errval, "Could not derive key - %s", kdf_error(fn));
    }

done:
    cipher_free_scrub(cipher);
    kdf_free_scrub(fn);
    return errval;
}

static void compute_imprint_size(size_t *random_data_size,
                                 size_t *total_imprint_size,
                                 const struct cipher_ctx *cipher,
                                 const struct chf_ctx *chf)
{
    size_t hash_len, block_len, key_len, max, required;

    /* Amount of random data is guaranteed to be as large as each of these */
    hash_len = chf_digest_size(chf);
    block_len = cipher_block_size(cipher);
    key_len = cipher_key_size(cipher);
    max = MAX(hash_len, block_len, key_len);

    /* The imprint also includes the hash of the random data */
    required = max + hash_len;
    ASSERT(required >= max, "Addition overflow computing imprint size");

    /*
     * The random data and its hash have to be a multiple of the cipher's block
     * size, so we might need to make the random data slightly larger, to fill
     * out a final block.
     */
    *total_imprint_size = cipher_block_ceiling(required, cipher);
    *random_data_size = (*total_imprint_size) - hash_len;
}

static size_t cipher_block_ceiling(size_t bytes,
                                   const struct cipher_ctx *cipher)
{
    size_t block_size, remainder, res;

    /* Ceiling to a multiple of the cipher's block size */
    block_size = cipher_block_size(cipher);
    remainder = bytes % block_size;
    if (remainder == 0) {
        return bytes;
    }
    else {
        res = bytes + (block_size - remainder);
        ASSERT(res >= bytes, "Addition overflow computing block ceiling");
        return res;
    }
}
