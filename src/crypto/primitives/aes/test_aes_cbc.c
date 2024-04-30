/*
 * Copyright (c) 2023-2024 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "crypto/primitives/aes/aes_cbc.h"
#include "crypto/test/framework.h"
#include "crypto/test/hex.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("AES-CBC");

/*
 * Directions in which to run an AES-CBC test, and a function pointer to either
 * the encryption or decryption operation.
 */
#define TEST_DIRECTION_ENCRYPT (0)
#define TEST_DIRECTION_DECRYPT (1)
typedef void (*aes_cbc_fptr)(struct aes_cbc_ctx *, const byte_t *, byte_t *);

/*
 * Parameters for a single- or multi-block AES-CBC test, including plaintext
 * and ciphertext to test for both correct encryption and correct decryption.
 */
struct aes_cbc_plain_test {
    const char *key;
    const char *iv;
    const char *plaintext;
    const char *ciphertext;
};

/*
 * Parameters for an AES-CBC test using the NIST Algorithm Validation Suite
 * (AESAVS) Monte Carlo Test (MCT) algorithm. Because the MCT algorithm isn't
 * symmetric, only one of encryption or decryption is tested.
 */
struct aes_cbc_monte_test {
    const int direction;
    const char *key;
    const char *iv;
    const char *plaintext;
    const char *ciphertext;
};

/*
 * Runs an AES-CBC regular single- or multi-block test, in both of the
 * directions that it can be run, and assert that both outputs are correct.
 */
static void run_aes_cbc_plain_test(const struct aes_cbc_plain_test *test);

/*
 * Runs an AES-CBC regular single- or multi-block test that has been parsed
 * from its hexadecimal string format. The key length must be a valid AES key
 * length.
 */
static void run_parsed_aes_cbc_plain_test(const byte_t *key, size_t keySize,
                                          const byte_t *iv,
                                          const byte_t *plaintext,
                                          const byte_t *ciphertext,
                                          size_t numBlocks);

/*
 * Runs an AES-CBC encryption or decryption operation over one or more blocks
 * of input.
 */
static void aes_cbc_multi_block(struct aes_cbc_ctx *ctx, const byte_t *input,
                                const byte_t *iv, byte_t *output,
                                size_t numBlocks, int direction);

/*
 * Runs a single AES-CBC NIST AESAVS MCT - CBC case, which includes a single
 * assertion: that the outcome of either the loop of encryptions or the loop of
 * decryptions is correct.
 */
static void run_aes_cbc_monte_test(const struct aes_cbc_monte_test *test);

/*
 * Runs a single AES-CBC NIST AESAVS MCT - CBC test case that has been parsed
 * from its hexadecimal string format. The key length must be a valid AES key
 * length.
 */
static void run_parsed_aes_cbc_monte_test(const byte_t *key, size_t keySize,
                                          const byte_t *iv,
                                          const byte_t *plaintext,
                                          const byte_t *ciphertext,
                                          int direction);

/*
 * Runs the inner loop of the NIST AESAVS MCT - CBC algorithm, encrypting or
 * decrypting blocks sequentially. The lastTwoOutBlocksI array must be at least
 * (2 * AES_CBC_BLOCK_SIZE) bytes in length.
 */
static void nist_monte_cbc_inner_loop(struct aes_cbc_ctx *ctx,
                                      const byte_t *inBlockIZero,
                                      const byte_t *ivI,
                                      byte_t *lastTwoOutBlocksI,
                                      aes_cbc_fptr operation);

/*
 * Modifies the contents of the keyI array, per the NIST AESAVS MCT algorithm,
 * based on the last two output blocks of the inner loop.
 */
static void nist_monte_cbc_compute_new_key(byte_t *keyI, size_t keySize,
                                           const byte_t *lastTwoOutBlocksI);

/*
 * Converts strings of hexadecimal characters to arrays of bytes, and ensures
 * that the number of key bytes converted is a valid AES key size and that the
 * IV is the correct AES-CBC IV size. The caller is responsible for freeing the
 * allocated byte arrays.
 */
static void parse_hex_to_bytes(const char *keyHex, byte_t **keyBytes,
                               size_t *keySize, const char *ivHex,
                               byte_t **ivBytes, const char *plaintextHex,
                               byte_t **plaintextBytes, size_t *plaintextLen,
                               const char *ciphertextHex,
                               byte_t **ciphertextBytes,
                               size_t *ciphertextLen);

/*
 * All of the plain single- or multi-block encryption and decryption AES-CBC
 * tests to run. Note that each test is run in both directions, so only the
 * "encryption" version of a test from the standards needs to be provided
 * below.
 */
static const struct aes_cbc_plain_test plainTests[] = {
    /* NIST SP 800-38A, Appendix F.2.1, CBC-AES128.Encrypt */
    {
        .key = "2B7E151628AED2A6ABF7158809CF4F3C",
        .iv = "000102030405060708090A0B0C0D0E0F",
        .plaintext =
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E513"
            "0C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        .ciphertext =
            "7649ABAC8119B246CEE98E9B12E9197D5086CB9B507219EE95DB113A917678B27"
            "3BED6B8E3C1743B7116E69E222295163FF1CAA1681FAC09120ECA307586E1A7",
    },

    /* NIST SP 800-38A, Appendix F.2.3, CBC-AES192.Encrypt */
    {
        .key = "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B",
        .iv = "000102030405060708090A0B0C0D0E0F",
        .plaintext =
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E513"
            "0C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        .ciphertext =
            "4F021DB243BC633D7178183A9FA071E8B4D9ADA9AD7DEDF4E5E738763F69145A5"
            "71B242012FB7AE07FA9BAAC3DF102E008B0E27988598881D920A9E64F5615CD",
    },

    /* NIST SP 800-38A, Appendix F.2.5, CBC-AES256.Encrypt */
    {
        .key =
            "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
        .iv = "000102030405060708090A0B0C0D0E0F",
        .plaintext =
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E513"
            "0C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        .ciphertext =
            "F58C4C04D6E5F1BA779EABFB5F7BFBD69CFC4E967EDB808D679F777BC6702C7D3"
            "9F23369A9D9BACFA530E26304231461B2EB05E2C39BE9FCDA6C19078C6A9D1B",
    },

    /*
     * RFC 3602, Section 4, Case #1, one-block AES-CBC 128. Plaintext is
     * "Single block msg".
     */
    {
        .key = "06A9214036B8A15B512E03D534120006",
        .iv = "3DAFBA429D9EB430B422DA802C9FAC41",
        .plaintext = "53696E676C6520626C6F636B206D7367",
        .ciphertext = "E353779C1079AEB82708942DBE77181A",
    },

    /* RFC 3602, Section 4, Case #2, two-block AES-CBC 128 */
    {
        .key = "C286696D887C9AA0611BBB3E2025A45A",
        .iv = "562E17996D093D28DDB3BA695A2E6F58",
        .plaintext =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        .ciphertext =
            "D296CD94C2CCCF8A3A863028B5E1DC0A7586602D253CFFF91B8266BEA6D61AB1",
    },

    /*
     * RFC 3602, Section 4, Case #3, three-block AES-CBC 128. Plaintext is
     * "This is a 48-byte message (exactly 3 AES blocks)".
     */
    {
        .key = "6C3EA0477630CE21A2CE334AA746C2CD",
        .iv = "C782DC4C098C66CBD9CD27D825682C81",
        .plaintext = "5468697320697320612034382D62797465206D657373616765202865"
                     "786163746C7920332041455320626C6F636B7329",
        .ciphertext = "D0A02B3836451753D493665D33F0E8862DEA54CDB293ABC75069392"
                      "76772F8D5021C19216BAD525C8579695D83BA2684",
    },

    /* RFC 3602, Section 4, Case #4, four-block AES-CBC 128 */
    {
        .key = "56E47A38C5598974BC46903DBA290349",
        .iv = "8CE82EEFBEA0DA3C44699ED7DB51B7D9",
        .plaintext =
            "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC"
            "0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF",
        .ciphertext =
            "C30E32FFEDC0774E6AFF6AF0869F71AA0F3AF07A9A31A9C684DB207EB0EF8E4E3"
            "5907AA632C3FFDF868BB7B29D3D46AD83CE9F9A102EE99D49A53E87F4C3DA55",
    },
};

/*
 * All of the NIST AESAVS MCT tests to run.
 */
static const struct aes_cbc_monte_test monteTests[] = {
    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled CBCMCT128,
     * [ENCRYPT], with COUNT=0 PLAINTEXT and COUNT=99 CIPHERTEXT.
     */
    {
        .direction = TEST_DIRECTION_ENCRYPT,
        .key = "8809E7DD3A959EE5D8DBB13F501F2274",
        .iv = "E5C0BB535D7D54572AD06D170A0E58AE",
        .plaintext = "1FD4EE65603E6130CFC2A82AB3D56C24",
        .ciphertext = "7BED7671C8913AA1330F193761523E67",
    },

    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled CBCMCT128,
     * [DECRYPT], with COUNT=0 CIPHERTEXT and COUNT=99 PLAINTEXT.
     */
    {
        .direction = TEST_DIRECTION_DECRYPT,
        .key = "287B07C78F8E3E1BE7C41B3D96C04E6E",
        .iv = "41B461F9464FD515D25413B4241002B8",
        .ciphertext = "7C54923B0490A9D4DE4EC1CE6790AA4D",
        .plaintext = "4769317B0562C45949C18B3855F8BF4A",
    },

    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled CBCMCT192,
     * [ENCRYPT], with COUNT=0 PLAINTEXT and COUNT=99 CIPHERTEXT.
     */
    {
        .direction = TEST_DIRECTION_ENCRYPT,
        .key = "DEA64F83CFE6A0A183DDBE865CFCA059B3C615C1623D63FC",
        .iv = "426FBC087B50B395C0FC81EF9FD6D1AA",
        .plaintext = "CD0B8C8A8179ECB171B64C894A4D60FD",
        .ciphertext = "E6457BFC3433E80299C52B2BE418F582",
    },

    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled CBCMCT192,
     * [DECRYPT], with COUNT=0 CIPHERTEXT and COUNT=99 PLAINTEXT.
     */
    {
        .direction = TEST_DIRECTION_DECRYPT,
        .key = "A24EBD4D7A080C28CAAE984B5098A9EA38CF7280E2C5F122",
        .iv = "C5AEB9B51AD5108371C59D0B90816310",
        .ciphertext = "EB2C4E2712591FF13B8AC7870C9C404C",
        .plaintext = "836424EADF8155AAF9A9A51391A1CF7E",
    },

    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled CBCMCT256,
     * [ENCRYPT], with COUNT=0 PLAINTEXT and COUNT=99 CIPHERTEXT.
     */
    {
        .direction = TEST_DIRECTION_ENCRYPT,
        .key =
            "632BAC4FE4DB44CFCF18CFA90B43F86F378611B8D968595EB89E7AE98624564A",
        .iv = "FF8127621BE616803E3F002377730185",
        .plaintext = "90ED17475F0A62BC381BA1F3FFBFFF33",
        .ciphertext = "BADE1667B42F537F0CB3F5573A949AAA",
    },

    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled CBCMCT256,
     * [DECRYPT], with COUNT=0 CIPHERTEXT and COUNT=99 PLAINTEXT.
     */
    {
        .direction = TEST_DIRECTION_DECRYPT,
        .key =
            "31397AD8CC79C519E0F46E0F70303587E38958D70723B771552336B7771F6311",
        .iv = "4139CB54EEAC3FCF36ED72941122C40F",
        .ciphertext = "27A1D5C10FE45B801D15F56E654A70F0",
        .plaintext = "9BE831799A79B0955241F308F0D5B2E1",
    },
};

/*
 * Run the AES-CBC tests and report the success rate.
 */
int main()
{
    size_t onTest;

    for (onTest = 0;
         onTest < sizeof(plainTests) / sizeof(struct aes_cbc_plain_test);
         onTest++) {
        run_aes_cbc_plain_test(&plainTests[onTest]);
    }

    for (onTest = 0;
         onTest < sizeof(monteTests) / sizeof(struct aes_cbc_monte_test);
         onTest++) {
        run_aes_cbc_monte_test(&monteTests[onTest]);
    }

    TEST_CONCLUDE();
}

static void run_aes_cbc_plain_test(const struct aes_cbc_plain_test *test)
{
    byte_t *key, *iv, *plaintext, *ciphertext;
    size_t keySize, plaintextLen, ciphertextLen;

    parse_hex_to_bytes(test->key, &key, &keySize, test->iv, &iv,
                       test->plaintext, &plaintext, &plaintextLen,
                       test->ciphertext, &ciphertext, &ciphertextLen);
    ASSERT(plaintextLen == ciphertextLen,
           "Plaintext and ciphertext sizes do not match");
    ASSERT(plaintextLen % AES_CBC_BLOCK_SIZE == 0,
           "Plaintext/ciphertext length not a block-size multiple");

    run_parsed_aes_cbc_plain_test(key, keySize, iv, plaintext, ciphertext,
                                  plaintextLen / AES_CBC_BLOCK_SIZE);

    free(key);
    free(iv);
    free(plaintext);
    free(ciphertext);
}

static void run_parsed_aes_cbc_plain_test(const byte_t *key, size_t keySize,
                                          const byte_t *iv,
                                          const byte_t *plaintext,
                                          const byte_t *ciphertext,
                                          size_t numBlocks)
{
    struct aes_cbc_ctx *ctx;
    byte_t *actual;
    size_t textLen;

    ctx = aes_cbc_alloc();
    textLen = numBlocks * AES_CBC_BLOCK_SIZE;
    actual = (byte_t *)calloc(textLen, 1);
    ASSERT_ALLOC(actual);

    aes_cbc_set_key(ctx, key, keySize);
    aes_cbc_multi_block(ctx, plaintext, iv, actual, numBlocks,
                        TEST_DIRECTION_ENCRYPT);
    TEST_ASSERT(memcmp(actual, ciphertext, textLen) == 0);

    memset(actual, 0, textLen);
    aes_cbc_multi_block(ctx, ciphertext, iv, actual, numBlocks,
                        TEST_DIRECTION_DECRYPT);
    TEST_ASSERT(memcmp(actual, plaintext, textLen) == 0);

    free(actual);
    aes_cbc_free_scrub(ctx);
}

static void aes_cbc_multi_block(struct aes_cbc_ctx *ctx, const byte_t *input,
                                const byte_t *iv, byte_t *output,
                                size_t numBlocks, int direction)
{
    size_t onBlock;
    aes_cbc_fptr operation;

    if (direction == TEST_DIRECTION_ENCRYPT) {
        operation = &aes_cbc_encrypt;
    }
    else {
        operation = &aes_cbc_decrypt;
    }

    aes_cbc_set_iv(ctx, iv);
    for (onBlock = 0; onBlock < numBlocks; onBlock++) {
        operation(ctx, input + onBlock * AES_CBC_BLOCK_SIZE,
                  output + onBlock * AES_CBC_BLOCK_SIZE);
    }
}

static void run_aes_cbc_monte_test(const struct aes_cbc_monte_test *test)
{
    byte_t *key, *iv, *plaintext, *ciphertext;
    size_t keySize, plaintextLen, ciphertextLen;

    parse_hex_to_bytes(test->key, &key, &keySize, test->iv, &iv,
                       test->plaintext, &plaintext, &plaintextLen,
                       test->ciphertext, &ciphertext, &ciphertextLen);
    ASSERT(plaintextLen == AES_CBC_BLOCK_SIZE, "Invalid plaintext length");
    ASSERT(ciphertextLen == AES_CBC_BLOCK_SIZE, "Inalid ciphertext length");

    run_parsed_aes_cbc_monte_test(key, keySize, iv, plaintext, ciphertext,
                                  test->direction);

    free(key);
    free(iv);
    free(plaintext);
    free(ciphertext);
}

static void run_parsed_aes_cbc_monte_test(const byte_t *key, size_t keySize,
                                          const byte_t *iv,
                                          const byte_t *plaintext,
                                          const byte_t *ciphertext,
                                          int direction)
{
    const int NIST_MONTE_OUTER_LOOP_SIZE = 100;
    struct aes_cbc_ctx *ctx;
    byte_t keyI[AES_CBC_KEY_SIZE_MAX];
    byte_t inBlockIZero[AES_CBC_BLOCK_SIZE];
    byte_t ivI[AES_CBC_IV_SIZE];
    byte_t lastTwoOutBlocksI[2 * AES_CBC_BLOCK_SIZE];
    const byte_t *expected;
    aes_cbc_fptr operation;
    int i;

    ctx = aes_cbc_alloc();
    memset(lastTwoOutBlocksI, 0, 2 * AES_CBC_BLOCK_SIZE);

    /*
     * The NIST AESAVS Monte Carlo Test - CBC algorithm is described on pages
     * 8-9 of the AESAVS document. The algorithm, rephrased for greater
     * clarity, uses these variables:
     *
     * key[i]          where 0 <= i < 100
     * iv[i]           where 0 <= i < 100
     * inBlock[i][j]   where 0 <= i < 100, 0 <= j < 1000
     * outBlock[i][j]  where 0 <= i < 100, 0 <= j < 1000
     *
     * inBlock represents the plaintexts and outBlock the ciphertext results
     * when the operation is encryption, and vice versa when the operation is
     * decryption.
     *
     * To begin:
     *
     * key[0] = seed key
     * iv[0] = seed IV
     * inBlock[0][0] = seed input block
     */
    memcpy(keyI, key, keySize);
    memcpy(ivI, iv, AES_CBC_IV_SIZE);
    if (direction == TEST_DIRECTION_ENCRYPT) {
        memcpy(inBlockIZero, plaintext, AES_CBC_BLOCK_SIZE);
        operation = &aes_cbc_encrypt;
        expected = ciphertext;
    }
    else {
        memcpy(inBlockIZero, ciphertext, AES_CBC_BLOCK_SIZE);
        operation = &aes_cbc_decrypt;
        expected = plaintext;
    }

    /*
     * for ( i = 0 to 99 ):
     *     inner loop computes outBlock[i][998] and outBlock[i][999] using
     *       inBlock[i][0], iv[i], and key[i]
     *     compute key[i+1] using key[i], outBlock[i][998], and
     *       outBlock[i][999]
     *     iv[i+1] = outBlock[i][999]
     *     inBlock[i+1][0] = outBlock[i][998]
     */
    for (i = 0; i < NIST_MONTE_OUTER_LOOP_SIZE; i++) {
        aes_cbc_set_key(ctx, keyI, keySize);
        nist_monte_cbc_inner_loop(ctx, inBlockIZero, ivI, lastTwoOutBlocksI,
                                  operation);
        if (i < NIST_MONTE_OUTER_LOOP_SIZE - 1) {
            nist_monte_cbc_compute_new_key(keyI, keySize, lastTwoOutBlocksI);
            memcpy(ivI, lastTwoOutBlocksI + AES_CBC_BLOCK_SIZE,
                   AES_CBC_IV_SIZE);
            memcpy(inBlockIZero, lastTwoOutBlocksI, AES_CBC_BLOCK_SIZE);
        }
    }

    /*
     * outBlock[99][999] is the expected result of the AES-CBC MCT.
     *
     * Note: in the AESAVS CAVP, each output[i][999] is output as an
     * intermediate computation. Here, we check only the final result.
     */
    TEST_ASSERT(memcmp(lastTwoOutBlocksI + AES_CBC_BLOCK_SIZE, expected,
                       AES_CBC_BLOCK_SIZE) == 0);
    aes_cbc_free_scrub(ctx);
}

static void nist_monte_cbc_inner_loop(struct aes_cbc_ctx *ctx,
                                      const byte_t *inBlockIZero,
                                      const byte_t *ivI,
                                      byte_t *lastTwoOutBlocksI,
                                      aes_cbc_fptr operation)
{
    const int NIST_MONTE_INNER_LOOP_SIZE = 1000;
    byte_t intermediate[AES_CBC_BLOCK_SIZE];
    int j;

    /*
     * outBlock[i][0] = AES(key[i], iv[i], inBlock[i][0])
     * inBlock[i][1] = iv[i]
     *
     * That is, the IV is set in the AES context for the first encryption (or
     * decryption) of this inner loop. Then, the IV itself becomes an input
     * block for the second encryption (or decryption). See just above the
     * "for" loop, below.
     */
    aes_cbc_set_iv(ctx, ivI);
    operation(ctx, inBlockIZero, lastTwoOutBlocksI);

    /*
     * for ( j = 1 to 999 ):
     *     outBlock[i][j] = AES(key, inBlock[i][j])
     *     inBlock[i][j+1] = outBlock[i][j-1]
     */
    operation(ctx, ivI, lastTwoOutBlocksI + AES_CBC_BLOCK_SIZE);
    for (j = 2; j < NIST_MONTE_INNER_LOOP_SIZE; j++) {
        operation(ctx, lastTwoOutBlocksI, intermediate);
        memcpy(lastTwoOutBlocksI, lastTwoOutBlocksI + AES_CBC_BLOCK_SIZE,
               AES_CBC_BLOCK_SIZE);
        memcpy(lastTwoOutBlocksI + AES_CBC_BLOCK_SIZE, intermediate,
               AES_CBC_BLOCK_SIZE);
    }
}

static void nist_monte_cbc_compute_new_key(byte_t *keyI, size_t keySize,
                                           const byte_t *lastTwoOutBlocksI)
{
    /*
     * if ( keySize = 128 ):
     *     key[i+1] = key[i] XOR outBlock[i][999]
     * if ( keySize = 192 ):
     *     key[i+1] = key[i] XOR
     *                ( last 64 bits of outBlock[i][998] + outBlock[i][999] )
     * if ( keySize = 256 ):
     *     key[i+1] = key[i] XOR ( outBlock[i][998] + outBlock[i][999] )
     */
    size_t onByte;

    lastTwoOutBlocksI += 2 * AES_CBC_BLOCK_SIZE - keySize;
    for (onByte = 0; onByte < keySize; onByte++) {
        keyI[onByte] ^= lastTwoOutBlocksI[onByte];
    }
}

static void parse_hex_to_bytes(const char *keyHex, byte_t **keyBytes,
                               size_t *keySize, const char *ivHex,
                               byte_t **ivBytes, const char *plaintextHex,
                               byte_t **plaintextBytes, size_t *plaintextLen,
                               const char *ciphertextHex,
                               byte_t **ciphertextBytes, size_t *ciphertextLen)
{
    size_t ivSize;

    hex_to_bytes(keyHex, keyBytes, keySize);
    hex_to_bytes(ivHex, ivBytes, &ivSize);
    hex_to_bytes(plaintextHex, plaintextBytes, plaintextLen);
    hex_to_bytes(ciphertextHex, ciphertextBytes, ciphertextLen);

    ASSERT(*keySize == AES_CBC_KEY_SIZE_128 ||
               *keySize == AES_CBC_KEY_SIZE_192 ||
               *keySize == AES_CBC_KEY_SIZE_256,
           "Invalid AES-CBC key size");
    ASSERT(ivSize == AES_CBC_IV_SIZE, "Invalid AES-CBC IV size");
}
