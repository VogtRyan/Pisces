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
#include "crypto/primitives/sha1/sha1.h"
#include "crypto/test/framework.h"

#include <stddef.h>
#include <string.h>

TEST_PREAMBLE("SHA1");
static struct sha1_ctx *ctx;

/*
 * Parameters for testing the output of a single invocation of the SHA-1
 * algorithm, where the input is a single message (potentially repeated
 * multiple times).
 */
#define PLAIN_TEST_MSG_LEN_MAX (163)
struct sha1_plain_test {
    size_t msgLen;
    size_t msgRepeats;
    const byte_t msg[PLAIN_TEST_MSG_LEN_MAX];
    const byte_t digest[SHA1_DIGEST_BYTES];
};

/*
 * Parameters for a SHA-1 test using the NIST Secure Hash Algorithm Validation
 * System (SHAVS) Monte Carlo Test (MCT) algorithm.
 */
struct sha1_monte_test {
    const byte_t seed[SHA1_DIGEST_BYTES];
    const byte_t output[SHA1_DIGEST_BYTES];
};

/*
 * Runs a SHA-1 single-output test, and asserts that the output matches the
 * expected digest in the given test parameters.
 */
static void run_sha1_plain_test(const struct sha1_plain_test *test);

/*
 * Adds the provided message to the currently running SHA-1 context. If the
 * message is larger than one block in size, it will be broken up and added in
 * three pieces (to test the functionality of adding partial blocks to the
 * context).
 */
static void add_single_message(const byte_t *msg, size_t msgLen);

/*
 * Runs a single SHA-1 NIST SHAVS MCT case, which includes a single assertion:
 * that the outcome of the loop of hash invocations is correct.
 */
static void run_sha1_monte_test(const struct sha1_monte_test *test);

/*
 * Runs the inner loop of the SHA-1 NIST SHAVS MCT algorithm, hashing a single
 * input seed sequentially and storing the result in the output array.
 */
static void nist_monte_sha1_inner_loop(const byte_t *seedJ,
                                       byte_t *lastDigestJ);

/*
 * All of the single-output SHA-1 tests to run.
 */
static const struct sha1_plain_test plainTests[] = {
    /*
     * NIST CAVP SHA Test Vectors for Hashing Byte-Oriented Messages, example
     * vector labelled ShortMsg, Len=0 (0 bytes).
     */
    {
        .msgLen = 0,
        .msgRepeats = 0,
        .msg = {},
        .digest = {0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
                   0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09},
    },

    /*
     * RFC 3174, Section 7.3, TEST1. Input text is "abc".
     */
    {
        .msgLen = 3,
        .msgRepeats = 1,
        .msg = {0x61, 0x62, 0x63},
        .digest = {0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
                   0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D},
    },

    /*
     * RFC 3174, Section 7.3, TEST2. Input text is
     * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".
     */
    {
        .msgLen = 56,
        .msgRepeats = 1,
        .msg = {0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 0x63, 0x64,
                0x65, 0x66, 0x64, 0x65, 0x66, 0x67, 0x65, 0x66, 0x67, 0x68,
                0x66, 0x67, 0x68, 0x69, 0x67, 0x68, 0x69, 0x6A, 0x68, 0x69,
                0x6A, 0x6B, 0x69, 0x6A, 0x6B, 0x6C, 0x6A, 0x6B, 0x6C, 0x6D,
                0x6B, 0x6C, 0x6D, 0x6E, 0x6C, 0x6D, 0x6E, 0x6F, 0x6D, 0x6E,
                0x6F, 0x70, 0x6E, 0x6F, 0x70, 0x71},
        .digest = {0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
                   0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1},
    },

    /*
     * RFC 3174, Section 7.3, TEST3. Input text is "a", repeated 1000000 times.
     */
    {
        .msgLen = 1,
        .msgRepeats = 1000000,
        .msg = {0x61},
        .digest = {0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
                   0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F},
    },

    /*
     * RFC 3174, Section 7.3, TEST4. Input text is
     * "0123456701234567012345670123456701234567012345670123456701234567",
     * repeated 10 times.
     */
    {
        .msgLen = 64,
        .msgRepeats = 10,
        .msg = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x30, 0x31,
                0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x30, 0x31, 0x32, 0x33,
                0x34, 0x35, 0x36, 0x37, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
                0x36, 0x37, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
                0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x30, 0x31,
                0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x30, 0x31, 0x32, 0x33,
                0x34, 0x35, 0x36, 0x37},
        .digest = {0xDE, 0xA3, 0x56, 0xA2, 0xCD, 0xDD, 0x90, 0xC7, 0xA7, 0xEC,
                   0xED, 0xC5, 0xEB, 0xB5, 0x63, 0x93, 0x4F, 0x46, 0x04, 0x52},
    },

    /*
     * NIST CAVP SHA Test Vectors for Hashing Byte-Oriented Messages, example
     * vector labelled ShortMsg, Len=24 (3 bytes).
     */
    {
        .msgLen = 3,
        .msgRepeats = 1,
        .msg = {0xDF, 0x4B, 0xD2},
        .digest = {0xBF, 0x36, 0xED, 0x5D, 0x74, 0x72, 0x7D, 0xFD, 0x5D, 0x78,
                   0x54, 0xEC, 0x6B, 0x1D, 0x49, 0x46, 0x8D, 0x8E, 0xE8, 0xAA},
    },

    /*
     * NIST CAVP SHA Test Vectors for Hashing Byte-Oriented Messages, example
     * vector labelled ShortMsg, Len=512 (64 bytes).
     */
    {
        .msgLen = 64,
        .msgRepeats = 1,
        .msg = {0x45, 0x92, 0x7E, 0x32, 0xDD, 0xF8, 0x01, 0xCA, 0xF3, 0x5E,
                0x18, 0xE7, 0xB5, 0x07, 0x8B, 0x7F, 0x54, 0x35, 0x27, 0x82,
                0x12, 0xEC, 0x6B, 0xB9, 0x9D, 0xF8, 0x84, 0xF4, 0x9B, 0x32,
                0x7C, 0x64, 0x86, 0xFE, 0xAE, 0x46, 0xBA, 0x18, 0x7D, 0xC1,
                0xCC, 0x91, 0x45, 0x12, 0x1E, 0x14, 0x92, 0xE6, 0xB0, 0x6E,
                0x90, 0x07, 0x39, 0x4D, 0xC3, 0x3B, 0x77, 0x48, 0xF8, 0x6A,
                0xC3, 0x20, 0x7C, 0xFE},
        .digest = {0xA7, 0x0C, 0xFB, 0xFE, 0x75, 0x63, 0xDD, 0x0E, 0x66, 0x5C,
                   0x7C, 0x67, 0x15, 0xA9, 0x6A, 0x8D, 0x75, 0x69, 0x50, 0xC0},
    },

    /*
     * NIST CAVP SHA Test Vectors for Hashing Byte-Oriented Messages, example
     * vector labelled LongMsg, Len=1304 (163 bytes).
     */
    {
        .msgLen = 163,
        .msgRepeats = 1,
        .msg = {0x7C, 0x9C, 0x67, 0x32, 0x3A, 0x1D, 0xF1, 0xAD, 0xBF, 0xE5,
                0xCE, 0xB4, 0x15, 0xEA, 0xEF, 0x01, 0x55, 0xEC, 0xE2, 0x82,
                0x0F, 0x4D, 0x50, 0xC1, 0xEC, 0x22, 0xCB, 0xA4, 0x92, 0x8A,
                0xC6, 0x56, 0xC8, 0x3F, 0xE5, 0x85, 0xDB, 0x6A, 0x78, 0xCE,
                0x40, 0xBC, 0x42, 0x75, 0x7A, 0xBA, 0x7E, 0x5A, 0x3F, 0x58,
                0x24, 0x28, 0xD6, 0xCA, 0x68, 0xD0, 0xC3, 0x97, 0x83, 0x36,
                0xA6, 0xEF, 0xB7, 0x29, 0x61, 0x3E, 0x8D, 0x99, 0x79, 0x01,
                0x62, 0x04, 0xBF, 0xD9, 0x21, 0x32, 0x2F, 0xDD, 0x52, 0x22,
                0x18, 0x35, 0x54, 0x44, 0x7D, 0xE5, 0xE6, 0xE9, 0xBB, 0xE6,
                0xED, 0xF7, 0x6D, 0x7B, 0x71, 0xE1, 0x8D, 0xC2, 0xE8, 0xD6,
                0xDC, 0x89, 0xB7, 0x39, 0x83, 0x64, 0xF6, 0x52, 0xFA, 0xFC,
                0x73, 0x43, 0x29, 0xAA, 0xFA, 0x3D, 0xCD, 0x45, 0xD4, 0xF3,
                0x1E, 0x38, 0x8E, 0x4F, 0xAF, 0xD7, 0xFC, 0x64, 0x95, 0xF3,
                0x7C, 0xA5, 0xCB, 0xAB, 0x7F, 0x54, 0xD5, 0x86, 0x46, 0x3D,
                0xA4, 0xBF, 0xEA, 0xA3, 0xBA, 0xE0, 0x9F, 0x7B, 0x8E, 0x92,
                0x39, 0xD8, 0x32, 0xB4, 0xF0, 0xA7, 0x33, 0xAA, 0x60, 0x9C,
                0xC1, 0xF8, 0xD4},
        .digest = {0xD8, 0xFD, 0x6A, 0x91, 0xEF, 0x3B, 0x6C, 0xED, 0x05, 0xB9,
                   0x83, 0x58, 0xA9, 0x91, 0x07, 0xC1, 0xFA, 0xC8, 0xC8, 0x07},
    },
};

/*
 * All of the SHA-1 NIST SHAVS MCT tests to run.
 */
static const struct sha1_monte_test monteTests[] = {
    /*
     * NIST CAVP MCT Vectors for SHA-1, example vector labelled SHA1Monte,
     * L=20, with the Seed as input and COUNT=99 as output.
     */
    {
        .seed = {0xDD, 0x4D, 0xF6, 0x44, 0xEA, 0xF3, 0xD8, 0x5B, 0xAC, 0xE2,
                 0xB2, 0x1A, 0xCC, 0xAA, 0x22, 0xB2, 0x88, 0x21, 0xF5, 0xCD},
        .output = {0x01, 0xB7, 0xBE, 0x5B, 0x70, 0xEF, 0x64, 0x84, 0x3A, 0x03,
                   0xFD, 0xBB, 0x3B, 0x24, 0x7A, 0x62, 0x78, 0xD2, 0xCB, 0xE1},
    },
};

/*
 * Run the SHA-1 tests and report the success rate.
 */
int main()
{
    size_t onTest;
    ctx = sha1_alloc();

    for (onTest = 0;
         onTest < sizeof(plainTests) / sizeof(struct sha1_plain_test);
         onTest++) {
        run_sha1_plain_test(&plainTests[onTest]);
    }

    for (onTest = 0;
         onTest < sizeof(monteTests) / sizeof(struct sha1_monte_test);
         onTest++) {
        run_sha1_monte_test(&monteTests[onTest]);
    }

    sha1_free_scrub(ctx);
    TEST_CONCLUDE();
}

static void run_sha1_plain_test(const struct sha1_plain_test *test)
{
    byte_t actual[SHA1_DIGEST_BYTES];
    size_t onRepeat;

    memset(actual, 0, SHA1_DIGEST_BYTES);

    sha1_start(ctx);
    for (onRepeat = 0; onRepeat < test->msgRepeats; onRepeat++) {
        add_single_message(test->msg, test->msgLen);
    }
    sha1_end(ctx, actual);

    TEST_ASSERT(memcmp(actual, test->digest, SHA1_DIGEST_BYTES) == 0);
}

static void add_single_message(const byte_t *msg, size_t msgLen)
{
    const size_t QUARTER_BLOCK_SIZE = SHA1_BLOCK_BYTES / 4;

    if (msgLen <= SHA1_BLOCK_BYTES) {
        sha1_add(ctx, msg, msgLen);
    }
    else {
        /* Test the functionality of breaking larger messages into parts */
        sha1_add(ctx, msg, QUARTER_BLOCK_SIZE);
        sha1_add(ctx, msg + QUARTER_BLOCK_SIZE,
                 msgLen - 2 * QUARTER_BLOCK_SIZE);
        sha1_add(ctx, msg + msgLen - QUARTER_BLOCK_SIZE, QUARTER_BLOCK_SIZE);
    }
}

static void run_sha1_monte_test(const struct sha1_monte_test *test)
{
    const int NIST_MONTE_OUTER_LOOP_SIZE = 100;
    const byte_t *seedJ;
    byte_t lastDigestJ[SHA1_DIGEST_BYTES];
    int j;

    memset(lastDigestJ, 0, SHA1_DIGEST_BYTES);

    /*
     * The SHA-1 NIST SHAVS Monte Carlo Test algorithm is described on page 9
     * of the SHAVS document. The algorithm, rephrased for greater clarity,
     * uses these variables:
     *
     * md[j][i]  where 0 <= j < 100, 0 <= i < 1003
     * seed[j]   where 0 <= j < 100
     *
     * To begin:
     *
     * seed[0] = the provided input seed
     */
    seedJ = test->seed;

    /*
     * for ( j = 0 to 99 ):
     *     inner loop computes md[j][1002] from seed[j]
     *     seed[j+1] = md[j][1002]
     */
    for (j = 0; j < NIST_MONTE_OUTER_LOOP_SIZE; j++) {
        nist_monte_sha1_inner_loop(seedJ, lastDigestJ);
        seedJ = lastDigestJ;
    }

    /*
     * md[99][1002] is the expected output of the SHA-1 MCT.
     *
     * Note: in the SHAVS CAVP, each md[j][1002] is output as an intermediate
     * computation. Here, we check only the final result.
     */
    TEST_ASSERT(memcmp(lastDigestJ, test->output, SHA1_DIGEST_BYTES) == 0);
}

static void nist_monte_sha1_inner_loop(const byte_t *seedJ,
                                       byte_t *lastDigestJ)
{
    const int NIST_MONTE_INNER_LOOP_SIZE = 1000;
    byte_t intermediates[2][SHA1_DIGEST_BYTES];
    int i;

    /*
     * md[j][0] = md[j][1] = md[j][2] = seed[j]
     */
    memcpy(intermediates[0], seedJ, SHA1_DIGEST_BYTES);
    memcpy(intermediates[1], seedJ, SHA1_DIGEST_BYTES);
    memmove(lastDigestJ, seedJ, SHA1_DIGEST_BYTES);

    /*
     * for ( i = 3 to 1002 ):
     *     md[j][i] = SHA( md[j][i-3] + md[j][i-2] + md[j][i-1] )
     */
    for (i = 0; i < NIST_MONTE_INNER_LOOP_SIZE; i++) {
        sha1_start(ctx);

        sha1_add(ctx, intermediates[0], SHA1_DIGEST_BYTES);
        sha1_add(ctx, intermediates[1], SHA1_DIGEST_BYTES);
        sha1_add(ctx, lastDigestJ, SHA1_DIGEST_BYTES);

        memcpy(intermediates[0], intermediates[1], SHA1_DIGEST_BYTES);
        memcpy(intermediates[1], lastDigestJ, SHA1_DIGEST_BYTES);
        sha1_end(ctx, lastDigestJ);
    }
}
