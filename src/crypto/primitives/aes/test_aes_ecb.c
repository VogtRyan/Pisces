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
#include "crypto/primitives/aes/aes_ecb.h"
#include "crypto/test/framework.h"

#include <string.h>

TEST_PREAMBLE("AES-ECB");
struct aes_ecb_ctx *ctx;

/*
 * Runs a loop, per the NIST Advanced Encryption Standard Algorithm Validation
 * Suite (AESAVS) Monte Carlo Test (MCT) specification, encrypting or
 * decrypting block sequentially 1000 times then storing the result in output.
 */
#define NIST_MONTE_LOOP_ENCRYPT (0)
#define NIST_MONTE_LOOP_DECRYPT (1)
static void nist_ecb_monte_loop(struct aes_ecb_ctx *ctx, const byte_t *block,
                                byte_t *output, int direction);

/*
 * Test AES-128 ECB encryption and decryption where the key is all zero bits
 * and the plaintext is all one bits.
 *
 * Expected results are from NIST CAVP Known Answer Test (KAT) Vectors for AES,
 * ECBVarTxt128, COUNT=127.
 */
static void test_128_key_zeros_plaintext_ones(void)
{
    const byte_t symmetricKey[AES_ECB_KEY_SIZE_128] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const byte_t plaintext[AES_ECB_BLOCK_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const byte_t ciphertext[AES_ECB_BLOCK_SIZE] = {
        0x3F, 0x5B, 0x8C, 0xC9, 0xEA, 0x85, 0x5A, 0x0A,
        0xFA, 0x73, 0x47, 0xD2, 0x3E, 0x8D, 0x66, 0x4E};

    byte_t actual[AES_ECB_BLOCK_SIZE];
    memset(actual, 0, AES_ECB_BLOCK_SIZE);
    aes_ecb_set_key(ctx, symmetricKey, AES_ECB_KEY_SIZE_128);

    aes_ecb_encrypt(ctx, plaintext, actual);
    TEST_ASSERT(memcmp(actual, ciphertext, sizeof(ciphertext)) == 0);
    aes_ecb_decrypt(ctx, ciphertext, actual);
    TEST_ASSERT(memcmp(actual, plaintext, sizeof(plaintext)) == 0);
}

/*
 * Test AES-192 ECB encryption and decryption where the key is all zero bits
 * and the plaintext is all one bits.
 *
 * Expected results are from NIST CAVP Known Answer Test (KAT) Vectors for AES,
 * ECBVarTxt192, COUNT=127.
 */
static void test_192_key_zeros_plaintext_ones(void)
{
    const byte_t symmetricKey[AES_ECB_KEY_SIZE_192] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const byte_t plaintext[AES_ECB_BLOCK_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const byte_t ciphertext[AES_ECB_BLOCK_SIZE] = {
        0xB1, 0x3D, 0xB4, 0xDA, 0x1F, 0x71, 0x8B, 0xC6,
        0x90, 0x47, 0x97, 0xC8, 0x2B, 0xCF, 0x2D, 0x32};

    byte_t actual[AES_ECB_BLOCK_SIZE];
    memset(actual, 0, AES_ECB_BLOCK_SIZE);
    aes_ecb_set_key(ctx, symmetricKey, AES_ECB_KEY_SIZE_192);

    aes_ecb_encrypt(ctx, plaintext, actual);
    TEST_ASSERT(memcmp(actual, ciphertext, sizeof(ciphertext)) == 0);
    aes_ecb_decrypt(ctx, ciphertext, actual);
    TEST_ASSERT(memcmp(actual, plaintext, sizeof(plaintext)) == 0);
}

/*
 * Test AES-256 ECB encryption and decryption where the key is all zero bits
 * and the plaintext is all one bits.
 *
 * Expected results are from NIST CAVP Known Answer Test (KAT) Vectors for AES,
 * ECBVarTxt256, COUNT=127.
 */
static void test_256_key_zeros_plaintext_ones(void)
{
    const byte_t symmetricKey[AES_ECB_KEY_SIZE_256] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const byte_t plaintext[AES_ECB_BLOCK_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const byte_t ciphertext[AES_ECB_BLOCK_SIZE] = {
        0xAC, 0xDA, 0xCE, 0x80, 0x78, 0xA3, 0x2B, 0x1A,
        0x18, 0x2B, 0xFA, 0x49, 0x87, 0xCA, 0x13, 0x47};

    byte_t actual[AES_ECB_BLOCK_SIZE];
    memset(actual, 0, AES_ECB_BLOCK_SIZE);
    aes_ecb_set_key(ctx, symmetricKey, AES_ECB_KEY_SIZE_256);

    aes_ecb_encrypt(ctx, plaintext, actual);
    TEST_ASSERT(memcmp(actual, ciphertext, sizeof(ciphertext)) == 0);
    aes_ecb_decrypt(ctx, ciphertext, actual);
    TEST_ASSERT(memcmp(actual, plaintext, sizeof(plaintext)) == 0);
}

/*
 * Test AES-128 ECB encryption and decryption with a random key and random
 * plaintext, looped 1000 times.
 *
 * Expected results are from NIST CAVP Monte Carlo Test (MCT) Vectors for AES,
 * ECBMCT128, [ENCRYPT] COUNT=0.
 */
static void test_128_monte_loop_random(void)
{
    const byte_t symmetricKey[AES_ECB_KEY_SIZE_128] = {
        0x13, 0x9A, 0x35, 0x42, 0x2F, 0x1D, 0x61, 0xDE,
        0x3C, 0x91, 0x78, 0x7F, 0xE0, 0x50, 0x7A, 0xFD};
    const byte_t plaintext[AES_ECB_BLOCK_SIZE] = {
        0xB9, 0x14, 0x5A, 0x76, 0x8B, 0x7D, 0xC4, 0x89,
        0xA0, 0x96, 0xB5, 0x46, 0xF4, 0x3B, 0x23, 0x1F};
    const byte_t ciphertext[AES_ECB_BLOCK_SIZE] = {
        0xD7, 0xC3, 0xFF, 0xAC, 0x90, 0x31, 0x23, 0x86,
        0x50, 0x90, 0x1E, 0x15, 0x73, 0x64, 0xC3, 0x86};

    byte_t actual[AES_ECB_BLOCK_SIZE];
    memset(actual, 0, AES_ECB_BLOCK_SIZE);
    aes_ecb_set_key(ctx, symmetricKey, AES_ECB_KEY_SIZE_128);

    nist_ecb_monte_loop(ctx, plaintext, actual, NIST_MONTE_LOOP_ENCRYPT);
    TEST_ASSERT(memcmp(actual, ciphertext, sizeof(ciphertext)) == 0);
    nist_ecb_monte_loop(ctx, ciphertext, actual, NIST_MONTE_LOOP_DECRYPT);
    TEST_ASSERT(memcmp(actual, plaintext, sizeof(plaintext)) == 0);
}

/*
 * Test AES-192 ECB encryption and decryption with a random key and random
 * plaintext, looped 1000 times.
 *
 * Expected results are from NIST CAVP Monte Carlo Test (MCT) Vectors for AES,
 * ECBMCT192, [ENCRYPT] COUNT=0.
 */
static void test_192_monte_loop_random(void)
{
    const byte_t symmetricKey[AES_ECB_KEY_SIZE_192] = {
        0xB9, 0xA6, 0x3E, 0x09, 0xE1, 0xDF, 0xC4, 0x2E,
        0x93, 0xA9, 0x0D, 0x9B, 0xAD, 0x73, 0x9E, 0x59,
        0x67, 0xAE, 0xF6, 0x72, 0xEE, 0xDD, 0x5D, 0xA9};
    const byte_t plaintext[AES_ECB_BLOCK_SIZE] = {
        0x85, 0xA1, 0xF7, 0xA5, 0x81, 0x67, 0xB3, 0x89,
        0xCD, 0xDC, 0x8A, 0x9F, 0xF1, 0x75, 0xEE, 0x26};
    const byte_t ciphertext[AES_ECB_BLOCK_SIZE] = {
        0xEE, 0x83, 0xD8, 0x52, 0x79, 0xE0, 0x22, 0xD2,
        0x04, 0x80, 0x31, 0xAB, 0xEE, 0xFB, 0xC4, 0xA4};

    byte_t actual[AES_ECB_BLOCK_SIZE];
    memset(actual, 0, AES_ECB_BLOCK_SIZE);
    aes_ecb_set_key(ctx, symmetricKey, AES_ECB_KEY_SIZE_192);

    nist_ecb_monte_loop(ctx, plaintext, actual, NIST_MONTE_LOOP_ENCRYPT);
    TEST_ASSERT(memcmp(actual, ciphertext, sizeof(ciphertext)) == 0);
    nist_ecb_monte_loop(ctx, ciphertext, actual, NIST_MONTE_LOOP_DECRYPT);
    TEST_ASSERT(memcmp(actual, plaintext, sizeof(plaintext)) == 0);
}

/*
 * Test AES-256 ECB encryption and decryption with a random key and random
 * plaintext, looped 1000 times.
 *
 * Expected results are from NIST CAVP Monte Carlo Test (MCT) Vectors for AES,
 * ECBMCT256, [ENCRYPT] COUNT=0.
 */
static void test_256_monte_loop_random(void)
{
    const byte_t symmetricKey[AES_ECB_KEY_SIZE_256] = {
        0xF9, 0xE8, 0x38, 0x9F, 0x5B, 0x80, 0x71, 0x2E, 0x38, 0x86, 0xCC,
        0x1F, 0xA2, 0xD2, 0x8A, 0x3B, 0x8C, 0x9C, 0xD8, 0x8A, 0x2D, 0x4A,
        0x54, 0xC6, 0xAA, 0x86, 0xCE, 0x0F, 0xEF, 0x94, 0x4B, 0xE0};
    const byte_t plaintext[AES_ECB_BLOCK_SIZE] = {
        0xB3, 0x79, 0x77, 0x7F, 0x90, 0x50, 0xE2, 0xA8,
        0x18, 0xF2, 0x94, 0x0C, 0xBB, 0xD9, 0xAB, 0xA4};
    const byte_t ciphertext[AES_ECB_BLOCK_SIZE] = {
        0x68, 0x93, 0xEB, 0xAF, 0x0A, 0x1F, 0xCC, 0xC7,
        0x04, 0x32, 0x65, 0x29, 0xFD, 0xFB, 0x60, 0xDB};

    byte_t actual[AES_ECB_BLOCK_SIZE];
    memset(actual, 0, AES_ECB_BLOCK_SIZE);
    aes_ecb_set_key(ctx, symmetricKey, AES_ECB_KEY_SIZE_256);

    nist_ecb_monte_loop(ctx, plaintext, actual, NIST_MONTE_LOOP_ENCRYPT);
    TEST_ASSERT(memcmp(actual, ciphertext, sizeof(ciphertext)) == 0);
    nist_ecb_monte_loop(ctx, ciphertext, actual, NIST_MONTE_LOOP_DECRYPT);
    TEST_ASSERT(memcmp(actual, plaintext, sizeof(plaintext)) == 0);
}

/*
 * Run the AES ECB tests and report the success rate.
 */
int main()
{
    ctx = aes_ecb_alloc();

    test_128_key_zeros_plaintext_ones();
    test_192_key_zeros_plaintext_ones();
    test_256_key_zeros_plaintext_ones();
    test_128_monte_loop_random();
    test_192_monte_loop_random();
    test_256_monte_loop_random();

    aes_ecb_free_scrub(ctx);
    TEST_CONCLUDE();
}

static void nist_ecb_monte_loop(struct aes_ecb_ctx *ctx, const byte_t *block,
                                byte_t *output, int direction)
{
    /*
     * Based on the NIST AESAVS specification, p.7:
     *
     * input[0] = input block
     * 
     * for j = 0 to 999
     *     output[j] = AES(key, input[j])
     *     input[j+1] = output[j]
     * 
     * Output output[999]
     * 
     * Note the operation is symmetric, so both encryption and decryption can
     * be tested with the same plaintext/ciphertext pair.
     */
    byte_t intermediate[AES_ECB_BLOCK_SIZE];
    const int NIST_MONTE_LOOP_SIZE = 1000;
    int i;

    memcpy(intermediate, block, AES_ECB_BLOCK_SIZE);
    for (i = 0; i < NIST_MONTE_LOOP_SIZE; i++) {
        if (direction == NIST_MONTE_LOOP_ENCRYPT) {
            aes_ecb_encrypt(ctx, intermediate, intermediate);
        }
        else {
            aes_ecb_decrypt(ctx, intermediate, intermediate);
        }
    }
    memcpy(output, intermediate, AES_ECB_BLOCK_SIZE);
}
