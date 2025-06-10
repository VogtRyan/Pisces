/*
 * Copyright (c) 2023-2025 Ryan Vogt <rvogt.ca@gmail.com>
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
#include "crypto/primitives/aes/aes_ecb.h"
#include "crypto/test/framework.h"
#include "crypto/test/hex.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("AES-ECB");

#define TEST_DIRECTION_ENCRYPT (0)
#define TEST_DIRECTION_DECRYPT (1)

/*
 * Function pointer to either the AES-ECB encryption function or AES-ECB
 * decryption function.
 */
typedef void (*aes_ecb_fptr)(struct aes_ecb_ctx *, const byte *, byte *);

/*
 * Single- or multi-block test of both encryption and decryption. Each test is
 * run in both directions, so only the "encryption" version of a test from the
 * standards needs to be provided.
 */
struct aes_ecb_plain_test {
    const char *key;
    const char *plaintext;
    const char *ciphertext;
};

/*
 * An AES-ECB test using the NIST Algorithm Validation Suite (AESAVS) Monte
 * Carlo Test (MCT) algorithm. Because the MCT algorithm isn't symmetric, only
 * one of encryption or decryption is tested.
 *
 * Tests contain only the final ciphertext or plaintext (not the checkpoint
 * values specified in the NIST CAVP MCT), because only the final value is
 * checked in this implementation.
 */
struct aes_ecb_monte_test {
    const int direction;
    const char *key;
    const char *plaintext;
    const char *ciphertext;
};

static void run_aes_ecb_plain_test(const struct aes_ecb_plain_test *test);
static void run_parsed_aes_ecb_plain_test(const byte *key, size_t key_size,
                                          const byte *plaintext,
                                          const byte *ciphertext,
                                          size_t num_blocks);

static void aes_ecb_multi_block(struct aes_ecb_ctx *ctx, const byte *input,
                                byte *output, size_t num_blocks,
                                int direction);

static void run_aes_ecb_monte_test(const struct aes_ecb_monte_test *test);
static void run_parsed_aes_ecb_monte_test(const byte *key, size_t key_size,
                                          const byte *plaintext,
                                          const byte *ciphertext,
                                          int direction);
static void nist_monte_ecb_inner_loop(struct aes_ecb_ctx *ctx,
                                      const byte *in_block_i_zero,
                                      byte *last_two_out_blocks_i,
                                      aes_ecb_fptr operation);
static void nist_monte_ecb_compute_new_key(byte *key_i, size_t key_size,
                                           const byte *last_two_out_blocks_i);

static void parse_hex_to_bytes(const char *key_hex, byte **key_bytes,
                               size_t *key_size, const char *plaintext_hex,
                               byte **plaintext_bytes, size_t *plaintext_len,
                               const char *ciphertext_hex,
                               byte **ciphertext_bytes,
                               size_t *ciphertext_len);

static const struct aes_ecb_plain_test plain_tests[] = {
    /* FIPS-197, Appendix C.1, AES-128 */
    {
        .key = "000102030405060708090A0B0C0D0E0F",
        .plaintext = "00112233445566778899AABBCCDDEEFF",
        .ciphertext = "69C4E0D86A7B0430D8CDB78070B4C55A",
    },

    /* FIPS-197, Appendix C.2, AES-192 */
    {
        .key = "000102030405060708090A0B0C0D0E0F1011121314151617",
        .plaintext = "00112233445566778899AABBCCDDEEFF",
        .ciphertext = "DDA97CA4864CDFE06EAF70A0EC0D7191",
    },

    /* FIPS-197, Appendix C.3, AES-256 */
    {
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
        .plaintext = "00112233445566778899AABBCCDDEEFF",
        .ciphertext = "8EA2B7CA516745BFEAFC49904B496089",
    },

    /* NIST SP 800-38A, Appendix F.1.1, ECB-AES128.Encrypt */
    {
        .key = "2B7E151628AED2A6ABF7158809CF4F3C",
        .plaintext =
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E513"
            "0C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        .ciphertext =
            "3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF4"
            "3B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4",
    },

    /* NIST SP 800-38A, Appendix F.1.3, ECB-AES192.Encrypt */
    {
        .key = "8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B",
        .plaintext =
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E513"
            "0C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        .ciphertext =
            "BD334F1D6E45F25FF712A214571FA5CC974104846D0AD3AD7734ECB3ECEE4EEFE"
            "F7AFD2270E2E60ADCE0BA2FACE6444E9A4B41BA738D6C72FB16691603C18E0E",
    },

    /* NIST SP 800-38A, Appendix F.1.5, ECB-AES256.Encrypt */
    {
        .key =
            "603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4",
        .plaintext =
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E513"
            "0C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710",
        .ciphertext =
            "F3EED1BDB5D2A03C064B5A7E3DB181F8591CCB10D410ED26DC5BA74A31362870B"
            "6ED21B99CA6F4F9F153E7B1BEAFED1D23304B7A39F9F3FF067D8D8F9E24ECC7",
    },

    /*
     * NIST CAVP Known Answer Test (KAT) Vectors for AES, example vector
     * labelled ECBVarTxt128, [ENCRYPT], COUNT=127.
     */
    {
        .key = "00000000000000000000000000000000",
        .plaintext = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        .ciphertext = "3F5B8CC9EA855A0AFA7347D23E8D664E",
    },

    /*
     * NIST CAVP Known Answer Test (KAT) Vectors for AES, example vector
     * labelled ECBVarTxt192, [ENCRYPT], COUNT=127.
     */
    {
        .key = "000000000000000000000000000000000000000000000000",
        .plaintext = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        .ciphertext = "B13DB4DA1F718BC6904797C82BCF2D32",
    },

    /*
     * NIST CAVP Known Answer Test (KAT) Vectors for AES, example vector
     * labelled ECBVarTxt256, [ENCRYPT], COUNT=127.
     */
    {
        .key =
            "0000000000000000000000000000000000000000000000000000000000000000",
        .plaintext = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        .ciphertext = "ACDACE8078A32B1A182BFA4987CA1347",
    },
};

static const struct aes_ecb_monte_test monte_tests[] = {
    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled ECBMCT128,
     * [ENCRYPT], with COUNT=0 PLAINTEXT and COUNT=99 CIPHERTEXT.
     */
    {
        .direction = TEST_DIRECTION_ENCRYPT,
        .key = "139A35422F1D61DE3C91787FE0507AFD",
        .plaintext = "B9145A768B7DC489A096B546F43B231F",
        .ciphertext = "FB2649694783B551EACD9D5DB6126D47",
    },

    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled ECBMCT128,
     * [DECRYPT], with COUNT=0 CIPHERTEXT and COUNT=99 PLAINTEXT.
     */
    {
        .direction = TEST_DIRECTION_DECRYPT,
        .key = "0C60E7BF20ADA9BAA9E1DDF0D1540726",
        .ciphertext = "B08A29B11A500EA3ACA42C36675B9785",
        .plaintext = "D1D2BFDC58FFCAD2341B095BCE55221E",
    },

    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled ECBMCT192,
     * [ENCRYPT], with COUNT=0 PLAINTEXT and COUNT=99 CIPHERTEXT.
     */
    {
        .direction = TEST_DIRECTION_ENCRYPT,
        .key = "B9A63E09E1DFC42E93A90D9BAD739E5967AEF672EEDD5DA9",
        .plaintext = "85A1F7A58167B389CDDC8A9FF175EE26",
        .ciphertext = "5D1196DA8F184975E240949A25104554",
    },

    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled ECBMCT192,
     * [DECRYPT], with COUNT=0 CIPHERTEXT and COUNT=99 PLAINTEXT.
     */
    {
        .direction = TEST_DIRECTION_DECRYPT,
        .key = "4B97585701C03FBEBDFA8555024F589F1482C58A00FDD9FD",
        .ciphertext = "D0BD0E02DED155E4516BE83F42D347A4",
        .plaintext = "B63EF1B79507A62EBA3DAFCEC54A6328",
    },

    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled ECBMCT256,
     * [ENCRYPT], with COUNT=0 PLAINTEXT and COUNT=99 CIPHERTEXT.
     */
    {
        .direction = TEST_DIRECTION_ENCRYPT,
        .key =
            "F9E8389F5B80712E3886CC1FA2D28A3B8C9CD88A2D4A54C6AA86CE0FEF944BE0",
        .plaintext = "B379777F9050E2A818F2940CBBD9ABA4",
        .ciphertext = "C5D2CB3D5B7FF0E23E308967EE074825",
    },

    /*
     * NIST CAVP MCT Vectors for AES, example vector labelled ECBMCT256,
     * [DECRYPT], with COUNT=0 CIPHERTEXT and COUNT=99 PLAINTEXT.
     */
    {
        .direction = TEST_DIRECTION_DECRYPT,
        .key =
            "2B09BA39B834062B9E93F48373B8DD018DEDF1E5BA1B8AF831EBBACBC92A2643",
        .ciphertext = "89649BD0115F30BD878567610223A59D",
        .plaintext = "E3D3868F578CAF34E36445BF14CEFC68",
    },
};

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(plain_tests) / sizeof(struct aes_ecb_plain_test);
         i++) {
        run_aes_ecb_plain_test(&plain_tests[i]);
    }

    for (i = 0; i < sizeof(monte_tests) / sizeof(struct aes_ecb_monte_test);
         i++) {
        run_aes_ecb_monte_test(&monte_tests[i]);
    }

    TEST_CONCLUDE();
}

static void run_aes_ecb_plain_test(const struct aes_ecb_plain_test *test)
{
    byte *key, *plaintext, *ciphertext;
    size_t key_size, plaintext_len, ciphertext_len;

    parse_hex_to_bytes(test->key, &key, &key_size, test->plaintext, &plaintext,
                       &plaintext_len, test->ciphertext, &ciphertext,
                       &ciphertext_len);
    ASSERT(plaintext_len == ciphertext_len,
           "Plaintext and ciphertext sizes do not match");
    ASSERT(plaintext_len % AES_ECB_BLOCK_SIZE == 0,
           "Plaintext/ciphertext length not a block-size multiple");

    run_parsed_aes_ecb_plain_test(key, key_size, plaintext, ciphertext,
                                  plaintext_len / AES_ECB_BLOCK_SIZE);

    free(key);
    free(plaintext);
    free(ciphertext);
}

static void run_parsed_aes_ecb_plain_test(const byte *key, size_t key_size,
                                          const byte *plaintext,
                                          const byte *ciphertext,
                                          size_t num_blocks)
{
    struct aes_ecb_ctx *ctx;
    byte *actual;
    size_t text_len;

    ctx = aes_ecb_alloc();
    text_len = num_blocks * AES_ECB_BLOCK_SIZE;
    actual = (byte *)calloc(text_len, 1);
    GUARD_ALLOC(actual);

    aes_ecb_set_key(ctx, key, key_size);
    aes_ecb_multi_block(ctx, plaintext, actual, num_blocks,
                        TEST_DIRECTION_ENCRYPT);
    TEST_ASSERT(memcmp(actual, ciphertext, text_len) == 0);

    memset(actual, 0, text_len);
    aes_ecb_multi_block(ctx, ciphertext, actual, num_blocks,
                        TEST_DIRECTION_DECRYPT);
    TEST_ASSERT(memcmp(actual, plaintext, text_len) == 0);

    free(actual);
    aes_ecb_free_scrub(ctx);
}

static void aes_ecb_multi_block(struct aes_ecb_ctx *ctx, const byte *input,
                                byte *output, size_t num_blocks, int direction)
{
    size_t on_block;
    aes_ecb_fptr operation;

    if (direction == TEST_DIRECTION_ENCRYPT) {
        operation = &aes_ecb_encrypt;
    }
    else {
        operation = &aes_ecb_decrypt;
    }

    for (on_block = 0; on_block < num_blocks; on_block++) {
        operation(ctx, input + on_block * AES_ECB_BLOCK_SIZE,
                  output + on_block * AES_ECB_BLOCK_SIZE);
    }
}

static void run_aes_ecb_monte_test(const struct aes_ecb_monte_test *test)
{
    byte *key, *plaintext, *ciphertext;
    size_t key_size, plaintext_len, ciphertext_len;

    parse_hex_to_bytes(test->key, &key, &key_size, test->plaintext, &plaintext,
                       &plaintext_len, test->ciphertext, &ciphertext,
                       &ciphertext_len);
    ASSERT(plaintext_len == AES_ECB_BLOCK_SIZE, "Invalid plaintext length");
    ASSERT(ciphertext_len == AES_ECB_BLOCK_SIZE, "Inalid ciphertext length");

    run_parsed_aes_ecb_monte_test(key, key_size, plaintext, ciphertext,
                                  test->direction);

    free(key);
    free(plaintext);
    free(ciphertext);
}

static void run_parsed_aes_ecb_monte_test(const byte *key, size_t key_size,
                                          const byte *plaintext,
                                          const byte *ciphertext,
                                          int direction)
{
    const int NIST_MONTE_OUTER_LOOP_SIZE = 100;
    struct aes_ecb_ctx *ctx;
    byte key_i[AES_ECB_KEY_SIZE_MAX];
    byte in_block_i_zero[AES_ECB_BLOCK_SIZE];
    byte last_two_out_blocks_i[2 * AES_ECB_BLOCK_SIZE];
    const byte *expected;
    aes_ecb_fptr operation;
    int i;

    ctx = aes_ecb_alloc();
    memset(last_two_out_blocks_i, 0, 2 * AES_ECB_BLOCK_SIZE);

    /*
     * The NIST AESAVS Monte Carlo Test - ECB algorithm is described on pages
     * 7-8 of the AESAVS document. The algorithm, rephrased for greater
     * clarity, uses these variables:
     *
     * key[i]           where 0 <= i < 100
     * in_block[i][j]   where 0 <= i < 100, 0 <= j < 1000
     * out_block[i][j]  where 0 <= i < 100, 0 <= j < 1000
     *
     * in_block represents the plaintexts and out_block the ciphertext results
     * when the operation is encryption, and vice versa when the operation is
     * decryption.
     *
     * To begin:
     *
     * key[0] = seed key
     * in_block[0][0] = seed input block
     */
    memcpy(key_i, key, key_size);
    if (direction == TEST_DIRECTION_ENCRYPT) {
        memcpy(in_block_i_zero, plaintext, AES_ECB_BLOCK_SIZE);
        operation = &aes_ecb_encrypt;
        expected = ciphertext;
    }
    else {
        memcpy(in_block_i_zero, ciphertext, AES_ECB_BLOCK_SIZE);
        operation = &aes_ecb_decrypt;
        expected = plaintext;
    }

    /*
     * for ( i = 0 to 99 ):
     *     inner loop computes out_block[i][998] and out_block[i][999] using
     *       in_block[i][0] and key[i]
     *     compute key[i+1] using key[i], out_block[i][998], and
     *       out_block[i][999]
     *     in_block[i+1][0] = out_block[i][999]
     */
    for (i = 0; i < NIST_MONTE_OUTER_LOOP_SIZE; i++) {
        aes_ecb_set_key(ctx, key_i, key_size);
        nist_monte_ecb_inner_loop(ctx, in_block_i_zero, last_two_out_blocks_i,
                                  operation);
        if (i < NIST_MONTE_OUTER_LOOP_SIZE - 1) {
            nist_monte_ecb_compute_new_key(key_i, key_size,
                                           last_two_out_blocks_i);
            memcpy(in_block_i_zero, last_two_out_blocks_i + AES_ECB_BLOCK_SIZE,
                   AES_ECB_BLOCK_SIZE);
        }
    }

    /*
     * out_block[99][999] is the expected result of the AES-ECB MCT.
     *
     * Note: in the AESAVS CAVP, each output[i][999] is output as an
     * intermediate computation. Here, we check only the final result.
     */
    TEST_ASSERT(memcmp(last_two_out_blocks_i + AES_ECB_BLOCK_SIZE, expected,
                       AES_ECB_BLOCK_SIZE) == 0);
    aes_ecb_free_scrub(ctx);
}

static void nist_monte_ecb_inner_loop(struct aes_ecb_ctx *ctx,
                                      const byte *in_block_i_zero,
                                      byte *last_two_out_blocks_i,
                                      aes_ecb_fptr operation)
{
    /*
     * The last_two_out_blocks_i array must be at least (2 *
     * AES_ECB_BLOCK_SIZE) bytes in length.
     */

    const int NIST_MONTE_INNER_LOOP_SIZE = 1000;
    int j;

    /*
     * for ( j = 0 to 999 ):
     *     out_block[i][j] = AES(key, in_block[i][j])
     *     in_block[j+1] = out_block[j]
     */
    operation(ctx, in_block_i_zero, last_two_out_blocks_i);
    for (j = 0; j < NIST_MONTE_INNER_LOOP_SIZE - 2; j++) {
        operation(ctx, last_two_out_blocks_i, last_two_out_blocks_i);
    }
    operation(ctx, last_two_out_blocks_i,
              last_two_out_blocks_i + AES_ECB_BLOCK_SIZE);
}

static void nist_monte_ecb_compute_new_key(byte *key_i, size_t key_size,
                                           const byte *last_two_out_blocks_i)
{
    /*
     * if ( key_size = 128 ):
     *     key[i+1] = key[i] XOR out_block[i][999]
     * if ( key_size = 192 ):
     *     key[i+1] = key[i] XOR
     *                ( last 64 bits of out_block[i][998] + out_block[i][999] )
     * if ( key_size = 256 ):
     *     key[i+1] = key[i] XOR ( out_block[i][998] + out_block[i][999] )
     */
    size_t on_byte;

    last_two_out_blocks_i += 2 * AES_ECB_BLOCK_SIZE - key_size;
    for (on_byte = 0; on_byte < key_size; on_byte++) {
        key_i[on_byte] ^= last_two_out_blocks_i[on_byte];
    }
}

static void parse_hex_to_bytes(const char *key_hex, byte **key_bytes,
                               size_t *key_size, const char *plaintext_hex,
                               byte **plaintext_bytes, size_t *plaintext_len,
                               const char *ciphertext_hex,
                               byte **ciphertext_bytes, size_t *ciphertext_len)
{
    hex_to_bytes(key_hex, key_bytes, key_size);
    hex_to_bytes(plaintext_hex, plaintext_bytes, plaintext_len);
    hex_to_bytes(ciphertext_hex, ciphertext_bytes, ciphertext_len);

    ASSERT(*key_size == AES_ECB_KEY_SIZE_128 ||
               *key_size == AES_ECB_KEY_SIZE_192 ||
               *key_size == AES_ECB_KEY_SIZE_256,
           "Invalid AES-ECB key size");
}
