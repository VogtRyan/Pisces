/*
 * Copyright (c) 2023 Ryan Vogt <rvogt.ca@gmail.com>
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
#include "crypto/primitives/aes/aes_cbc.h"
#include "crypto/test/framework.h"

#include <string.h>

TEST_PREAMBLE("AES-CBC");
struct aes_cbc_ctx *ctx;

/*
 * Runs a loop, per the NIST Advanced Encryption Standard Algorithm Validation
 * Suite (AESAVS) Monte Carlo Test (MCT) specification, encrypting or
 * decrypting starting with the given block and IV.
 */
#define NIST_MONTE_LOOP_ENCRYPT (0)
#define NIST_MONTE_LOOP_DECRYPT (1)
static void nist_cbc_monte_loop(struct aes_cbc_ctx *ctx, const byte_t *input,
                                const byte_t *iv, byte_t *output,
                                int direction);

/*
 * Test AES-128 CBC encryption with a random key, random IV, and random
 * plaintext per the NIST AESAVS Monte Carlo CBC algorithm.
 *
 * Expected results are from NIST CAVP Monte Carlo Test (MCT) Vectors for AES,
 * CBCMCT128, [ENCRYPT] COUNT=0.
 */
static void test_128_monte_loop_encrypt(void)
{
    const byte_t symmetricKey[AES_CBC_KEY_SIZE_128] = {
        0x88, 0x09, 0xE7, 0xDD, 0x3A, 0x95, 0x9E, 0xE5,
        0xD8, 0xDB, 0xB1, 0x3F, 0x50, 0x1F, 0x22, 0x74};
    const byte_t initVec[AES_CBC_IV_SIZE] = {
        0xE5, 0xC0, 0xBB, 0x53, 0x5D, 0x7D, 0x54, 0x57,
        0x2A, 0xD0, 0x6D, 0x17, 0x0A, 0x0E, 0x58, 0xAE};
    const byte_t plaintext[AES_CBC_BLOCK_SIZE] = {
        0x1F, 0xD4, 0xEE, 0x65, 0x60, 0x3E, 0x61, 0x30,
        0xCF, 0xC2, 0xA8, 0x2A, 0xB3, 0xD5, 0x6C, 0x24};
    const byte_t ciphertext[AES_CBC_BLOCK_SIZE] = {
        0xB1, 0x27, 0xA5, 0xB4, 0xC4, 0x69, 0x2D, 0x87,
        0x48, 0x3D, 0xB0, 0xC3, 0xB0, 0xD1, 0x1E, 0x64};

    byte_t actual[AES_CBC_BLOCK_SIZE];
    aes_cbc_set_key(ctx, symmetricKey, AES_CBC_KEY_SIZE_128);
    nist_cbc_monte_loop(ctx, plaintext, initVec, actual,
                        NIST_MONTE_LOOP_ENCRYPT);
    TEST_ASSERT(memcmp(actual, ciphertext, sizeof(ciphertext)) == 0);
}

/*
 * Test AES-192 CBC encryption with a random key, random IV, and random
 * plaintext per the NIST AESAVS Monte Carlo CBC algorithm.
 *
 * Expected results are from NIST CAVP Monte Carlo Test (MCT) Vectors for AES,
 * CBCMCT192, [ENCRYPT] COUNT=0.
 */
static void test_192_monte_loop_encrypt(void)
{
    const byte_t symmetricKey[AES_CBC_KEY_SIZE_192] = {
        0xDE, 0xA6, 0x4F, 0x83, 0xCF, 0xE6, 0xA0, 0xA1,
        0x83, 0xDD, 0xBE, 0x86, 0x5C, 0xFC, 0xA0, 0x59,
        0xB3, 0xC6, 0x15, 0xC1, 0x62, 0x3D, 0x63, 0xFC};
    const byte_t initVec[AES_CBC_IV_SIZE] = {
        0x42, 0x6F, 0xBC, 0x08, 0x7B, 0x50, 0xB3, 0x95,
        0xC0, 0xFC, 0x81, 0xEF, 0x9F, 0xD6, 0xD1, 0xAA};
    const byte_t plaintext[AES_CBC_BLOCK_SIZE] = {
        0xCD, 0x0B, 0x8C, 0x8A, 0x81, 0x79, 0xEC, 0xB1,
        0x71, 0xB6, 0x4C, 0x89, 0x4A, 0x4D, 0x60, 0xFD};
    const byte_t ciphertext[AES_CBC_BLOCK_SIZE] = {
        0xAE, 0x63, 0x02, 0xD2, 0x2D, 0xA9, 0x45, 0x81,
        0x17, 0xF5, 0x68, 0x14, 0x31, 0xFC, 0x80, 0xDF};

    byte_t actual[AES_CBC_BLOCK_SIZE];
    aes_cbc_set_key(ctx, symmetricKey, AES_CBC_KEY_SIZE_192);
    nist_cbc_monte_loop(ctx, plaintext, initVec, actual,
                        NIST_MONTE_LOOP_ENCRYPT);
    TEST_ASSERT(memcmp(actual, ciphertext, sizeof(ciphertext)) == 0);
}

/*
 * Test AES-256 CBC encryption with a random key, random IV, and random
 * plaintext per the NIST AESAVS Monte Carlo CBC algorithm.
 *
 * Expected results are from NIST CAVP Monte Carlo Test (MCT) Vectors for AES,
 * CBCMCT256, [ENCRYPT] COUNT=0.
 */
static void test_256_monte_loop_encrypt(void)
{
    const byte_t symmetricKey[AES_CBC_KEY_SIZE_256] = {
        0x63, 0x2B, 0xAC, 0x4F, 0xE4, 0xDB, 0x44, 0xCF, 0xCF, 0x18, 0xCF,
        0xA9, 0x0B, 0x43, 0xF8, 0x6F, 0x37, 0x86, 0x11, 0xB8, 0xD9, 0x68,
        0x59, 0x5E, 0xB8, 0x9E, 0x7A, 0xE9, 0x86, 0x24, 0x56, 0x4A};
    const byte_t initVec[AES_CBC_IV_SIZE] = {
        0xFF, 0x81, 0x27, 0x62, 0x1B, 0xE6, 0x16, 0x80,
        0x3E, 0x3F, 0x00, 0x23, 0x77, 0x73, 0x01, 0x85};
    const byte_t plaintext[AES_CBC_BLOCK_SIZE] = {
        0x90, 0xED, 0x17, 0x47, 0x5F, 0x0A, 0x62, 0xBC,
        0x38, 0x1B, 0xA1, 0xF3, 0xFF, 0xBF, 0xFF, 0x33};
    const byte_t ciphertext[AES_CBC_BLOCK_SIZE] = {
        0x44, 0x94, 0x03, 0x0B, 0x1E, 0x82, 0x8F, 0x57,
        0xE3, 0x49, 0xCB, 0xDE, 0x64, 0x99, 0xAB, 0xF3};

    byte_t actual[AES_CBC_BLOCK_SIZE];
    aes_cbc_set_key(ctx, symmetricKey, AES_CBC_KEY_SIZE_256);
    nist_cbc_monte_loop(ctx, plaintext, initVec, actual,
                        NIST_MONTE_LOOP_ENCRYPT);
    TEST_ASSERT(memcmp(actual, ciphertext, sizeof(ciphertext)) == 0);
}

/*
 * Test AES-128 CBC decryption with a random key, random IV, and random
 * plaintext per the NIST AESAVS Monte Carlo CBC algorithm.
 *
 * Expected results are from NIST CAVP Monte Carlo Test (MCT) Vectors for AES,
 * CBCMCT128, [DECRYPT] COUNT=0.
 */
static void test_128_monte_loop_decrypt(void)
{
    const byte_t symmetricKey[AES_CBC_KEY_SIZE_128] = {
        0x28, 0x7B, 0x07, 0xC7, 0x8F, 0x8E, 0x3E, 0x1B,
        0xE7, 0xC4, 0x1B, 0x3D, 0x96, 0xC0, 0x4E, 0x6E};
    const byte_t initVec[AES_CBC_IV_SIZE] = {
        0x41, 0xB4, 0x61, 0xF9, 0x46, 0x4F, 0xD5, 0x15,
        0xD2, 0x54, 0x13, 0xB4, 0x24, 0x10, 0x02, 0xB8};
    const byte_t ciphertext[AES_CBC_BLOCK_SIZE] = {
        0x7C, 0x54, 0x92, 0x3B, 0x04, 0x90, 0xA9, 0xD4,
        0xDE, 0x4E, 0xC1, 0xCE, 0x67, 0x90, 0xAA, 0x4D};
    const byte_t plaintext[AES_CBC_BLOCK_SIZE] = {
        0x28, 0x05, 0xD1, 0x0B, 0x12, 0x7F, 0xCD, 0x1D,
        0xA5, 0x28, 0xFA, 0xAD, 0x4E, 0xB2, 0xE1, 0x0B};

    byte_t actual[AES_CBC_BLOCK_SIZE];
    aes_cbc_set_key(ctx, symmetricKey, AES_CBC_KEY_SIZE_128);
    nist_cbc_monte_loop(ctx, ciphertext, initVec, actual,
                        NIST_MONTE_LOOP_DECRYPT);
    TEST_ASSERT(memcmp(actual, plaintext, sizeof(plaintext)) == 0);
}

/*
 * Test AES-192 CBC decryption with a random key, random IV, and random
 * plaintext per the NIST AESAVS Monte Carlo CBC algorithm.
 *
 * Expected results are from NIST CAVP Monte Carlo Test (MCT) Vectors for AES,
 * CBCMCT192, [DECRYPT] COUNT=0.
 */
static void test_192_monte_loop_decrypt(void)
{
    const byte_t symmetricKey[AES_CBC_KEY_SIZE_192] = {
        0xA2, 0x4E, 0xBD, 0x4D, 0x7A, 0x08, 0x0C, 0x28,
        0xCA, 0xAE, 0x98, 0x4B, 0x50, 0x98, 0xA9, 0xEA,
        0x38, 0xCF, 0x72, 0x80, 0xE2, 0xC5, 0xF1, 0x22};
    const byte_t initVec[AES_CBC_IV_SIZE] = {
        0xC5, 0xAE, 0xB9, 0xB5, 0x1A, 0xD5, 0x10, 0x83,
        0x71, 0xC5, 0x9D, 0x0B, 0x90, 0x81, 0x63, 0x10};
    const byte_t ciphertext[AES_CBC_BLOCK_SIZE] = {
        0xEB, 0x2C, 0x4E, 0x27, 0x12, 0x59, 0x1F, 0xF1,
        0x3B, 0x8A, 0xC7, 0x87, 0x0C, 0x9C, 0x40, 0x4C};
    const byte_t plaintext[AES_CBC_BLOCK_SIZE] = {
        0x88, 0x6D, 0xC6, 0xEE, 0x87, 0x74, 0xE7, 0xA5,
        0xB3, 0x78, 0xAC, 0x8A, 0x2B, 0x63, 0x7E, 0x50};

    byte_t actual[AES_CBC_BLOCK_SIZE];
    aes_cbc_set_key(ctx, symmetricKey, AES_CBC_KEY_SIZE_192);
    nist_cbc_monte_loop(ctx, ciphertext, initVec, actual,
                        NIST_MONTE_LOOP_DECRYPT);
    TEST_ASSERT(memcmp(actual, plaintext, sizeof(plaintext)) == 0);
}

/*
 * Test AES-256 CBC decryption with a random key, random IV, and random
 * plaintext per the NIST AESAVS Monte Carlo CBC algorithm.
 *
 * Expected results are from NIST CAVP Monte Carlo Test (MCT) Vectors for AES,
 * CBCMCT256, [DECRYPT] COUNT=0.
 */
static void test_256_monte_loop_decrypt(void)
{
    const byte_t symmetricKey[AES_CBC_KEY_SIZE_256] = {
        0x31, 0x39, 0x7A, 0xD8, 0xCC, 0x79, 0xC5, 0x19, 0xE0, 0xF4, 0x6E,
        0x0F, 0x70, 0x30, 0x35, 0x87, 0xE3, 0x89, 0x58, 0xD7, 0x07, 0x23,
        0xB7, 0x71, 0x55, 0x23, 0x36, 0xB7, 0x77, 0x1F, 0x63, 0x11};
    const byte_t initVec[AES_CBC_IV_SIZE] = {
        0x41, 0x39, 0xCB, 0x54, 0xEE, 0xAC, 0x3F, 0xCF,
        0x36, 0xED, 0x72, 0x94, 0x11, 0x22, 0xC4, 0x0F};
    const byte_t ciphertext[AES_CBC_BLOCK_SIZE] = {
        0x27, 0xA1, 0xD5, 0xC1, 0x0F, 0xE4, 0x5B, 0x80,
        0x1D, 0x15, 0xF5, 0x6E, 0x65, 0x4A, 0x70, 0xF0};
    const byte_t plaintext[AES_CBC_BLOCK_SIZE] = {
        0xF0, 0xE5, 0x0E, 0x03, 0x6B, 0xAF, 0x80, 0xCE,
        0xF5, 0x66, 0xD3, 0xF9, 0xEA, 0xA2, 0xA9, 0xA7};

    byte_t actual[AES_CBC_BLOCK_SIZE];
    aes_cbc_set_key(ctx, symmetricKey, AES_CBC_KEY_SIZE_256);
    nist_cbc_monte_loop(ctx, ciphertext, initVec, actual,
                        NIST_MONTE_LOOP_DECRYPT);
    TEST_ASSERT(memcmp(actual, plaintext, sizeof(plaintext)) == 0);
}

/*
 * Run the AES CBC tests and report the success rate.
 */
int main()
{
    ctx = aes_cbc_alloc();

    test_128_monte_loop_encrypt();
    test_192_monte_loop_encrypt();
    test_256_monte_loop_encrypt();
    test_128_monte_loop_decrypt();
    test_192_monte_loop_decrypt();
    test_256_monte_loop_decrypt();

    aes_cbc_free_scrub(ctx);
    TEST_CONCLUDE();
}

static void nist_cbc_monte_loop(struct aes_cbc_ctx *ctx, const byte_t *input,
                                const byte_t *iv, byte_t *output,
                                int direction)
{
    /*
     * Based on the NIST AESAVS specification, p.8:
     *
     * input[0] = input block
     *
     * for j = 0 to 999
     *     if ( j = 0 )
     *         output[j] = AES(key, iv, input[j])
     *         input[j+1] = iv
     *     else
     *         output[j] = AES(key, input[j])
     *         input[j+1] = output[j-1]
     *
     * Output output[999]
     *
     * Note the operation is not symmetric, so only encryption or decryption
     * can be tested with a given (plaintext, ciphertext, IV) tuple.
     */
    byte_t intermediate[2][AES_CBC_BLOCK_SIZE];
    const int NIST_MONTE_LOOP_SIZE = 1000;
    int i;

    memset(output, 0, AES_CBC_BLOCK_SIZE);
    aes_cbc_set_iv(ctx, iv);
    if (direction == NIST_MONTE_LOOP_ENCRYPT) {
        aes_cbc_encrypt(ctx, input, intermediate[0]);
        aes_cbc_encrypt(ctx, iv, intermediate[1]);
    }
    else {
        aes_cbc_decrypt(ctx, input, intermediate[0]);
        aes_cbc_decrypt(ctx, iv, intermediate[1]);
    }

    for (i = 2; i < NIST_MONTE_LOOP_SIZE; i++) {
        if (direction == NIST_MONTE_LOOP_ENCRYPT) {
            aes_cbc_encrypt(ctx, intermediate[0], output);
        }
        else {
            aes_cbc_decrypt(ctx, intermediate[0], output);
        }
        memcpy(intermediate[0], intermediate[1], AES_CBC_BLOCK_SIZE);
        memcpy(intermediate[1], output, AES_CBC_BLOCK_SIZE);
    }
}
