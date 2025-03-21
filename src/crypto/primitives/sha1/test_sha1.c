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
#include "crypto/primitives/sha1/sha1.h"
#include "crypto/test/framework.h"
#include "crypto/test/hex.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("SHA1");

/*
 * Parameters for testing the output of a single invocation of the SHA-1
 * algorithm, where the input is a single message (potentially repeated
 * multiple times).
 */
struct sha1_plain_test {
    size_t msgRepeats;
    const char *msg;
    const char *digest;
};

/*
 * Parameters for a SHA-1 test using the NIST Secure Hash Algorithm Validation
 * System (SHAVS) Monte Carlo Test (MCT) algorithm.
 */
struct sha1_monte_test {
    const char *seed;
    const char *output;
};

/*
 * Runs a SHA-1 single-output test, and asserts that the output matches the
 * expected digest in the given test parameters.
 */
static void run_sha1_plain_test(const struct sha1_plain_test *test);

/*
 * Runs a SHA-1 single-output test which has been parsed from its hexadecimal
 * string format. The digest length must match the length of a SHA-1 digest.
 */
static void run_parsed_sha1_plain_test(const byte_t *msg, size_t msgLen,
                                       size_t msgRepeats,
                                       const byte_t *digest);

/*
 * Adds the provided message to the currently running SHA-1 context. If the
 * message is larger than one block in size, it will be broken up and added in
 * three pieces (to test the functionality of adding partial blocks to the
 * context).
 */
static void add_single_message(struct sha1_ctx *ctx, const byte_t *msg,
                               size_t msgLen);

/*
 * Runs a single SHA-1 NIST SHAVS MCT case, which includes a single assertion:
 * that the outcome of the loop of hash invocations is correct.
 */
static void run_sha1_monte_test(const struct sha1_monte_test *test);

/*
 * Runs a single SHA-1 NIST SHAVS MCT case, which has been parsed from its
 * hexadecimal string format. Both the seed and the output must match the
 * length of a SHA-1 digest.
 */
static void run_parsed_sha1_monte_test(const byte_t *seed,
                                       const byte_t *output);

/*
 * Runs the inner loop of the SHA-1 NIST SHAVS MCT algorithm, hashing a single
 * input seed sequentially and storing the result in the output array.
 */
static void nist_monte_sha1_inner_loop(struct sha1_ctx *ctx,
                                       const byte_t *seedJ,
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
        .msgRepeats = 0,
        .msg = "",
        .digest = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
    },

    /*
     * RFC 3174, Section 7.3, TEST1. Input text is "abc".
     */
    {
        .msgRepeats = 1,
        .msg = "616263",
        .digest = "A9993E364706816ABA3E25717850C26C9CD0D89D",
    },

    /*
     * RFC 3174, Section 7.3, TEST2. Input text is
     * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".
     */
    {
        .msgRepeats = 1,
        .msg = "6162636462636465636465666465666765666768666768696768696A68696A"
               "6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
        .digest = "84983E441C3BD26EBAAE4AA1F95129E5E54670F1",
    },

    /*
     * RFC 3174, Section 7.3, TEST3. Input text is "a", repeated 1000000
     * times.
     */
    {
        .msgRepeats = 1000000,
        .msg = "61",
        .digest = "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F",
    },

    /*
     * RFC 3174, Section 7.3, TEST4. Input text is
     * "0123456701234567012345670123456701234567012345670123456701234567",
     * repeated 10 times.
     */
    {
        .msgRepeats = 10,
        .msg = "3031323334353637303132333435363730313233343536373031323334"
               "3536373031323334353637303132333435363730313233343536373031"
               "323334353637",
        .digest = "DEA356A2CDDD90C7A7ECEDC5EBB563934F460452",
    },

    /*
     * NIST CAVP SHA Test Vectors for Hashing Byte-Oriented Messages,
     * example vector labelled ShortMsg, Len=24 (3 bytes).
     */
    {
        .msgRepeats = 1,
        .msg = "DF4BD2",
        .digest = "BF36ED5D74727DFD5D7854EC6B1D49468D8EE8AA",
    },

    /*
     * NIST CAVP SHA Test Vectors for Hashing Byte-Oriented Messages,
     * example vector labelled ShortMsg, Len=512 (64 bytes).
     */
    {
        .msgRepeats = 1,
        .msg = "45927E32DDF801CAF35E18E7B5078B7F5435278212EC6BB99DF884F49B"
               "327C6486FEAE46BA187DC1CC9145121E1492E6B06E9007394DC33B7748"
               "F86AC3207CFE",
        .digest = "A70CFBFE7563DD0E665C7C6715A96A8D756950C0",
    },

    /*
     * NIST CAVP SHA Test Vectors for Hashing Byte-Oriented Messages,
     * example vector labelled LongMsg, Len=1304 (163 bytes).
     */
    {
        .msgRepeats = 1,
        .msg = "7C9C67323A1DF1ADBFE5CEB415EAEF0155ECE2820F4D50C1EC22CBA492"
               "8AC656C83FE585DB6A78CE40BC42757ABA7E5A3F582428D6CA68D0C397"
               "8336A6EFB729613E8D9979016204BFD921322FDD5222183554447DE5E6"
               "E9BBE6EDF76D7B71E18DC2E8D6DC89B7398364F652FAFC734329AAFA3D"
               "CD45D4F31E388E4FAFD7FC6495F37CA5CBAB7F54D586463DA4BFEAA3BA"
               "E09F7B8E9239D832B4F0A733AA609CC1F8D4",
        .digest = "D8FD6A91EF3B6CED05B98358A99107C1FAC8C807",
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
        .seed = "DD4DF644EAF3D85BACE2B21ACCAA22B28821F5CD",
        .output = "01B7BE5B70EF64843A03FDBB3B247A6278D2CBE1",
    },
};

/*
 * Run the SHA-1 tests and report the success rate.
 */
int main(void)
{
    size_t onTest;

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

    TEST_CONCLUDE();
}

static void run_sha1_plain_test(const struct sha1_plain_test *test)
{
    byte_t *msg, *digest;
    size_t msgLen, digestLen;

    hex_to_bytes(test->msg, &msg, &msgLen);
    hex_to_bytes(test->digest, &digest, &digestLen);
    ASSERT(digestLen == SHA1_DIGEST_BYTES, "Invalid digest size");

    run_parsed_sha1_plain_test(msg, msgLen, test->msgRepeats, digest);

    free(msg);
    free(digest);
}

static void run_parsed_sha1_plain_test(const byte_t *msg, size_t msgLen,
                                       size_t msgRepeats, const byte_t *digest)
{
    struct sha1_ctx *ctx;
    byte_t actual[SHA1_DIGEST_BYTES];
    size_t onRepeat;

    ctx = sha1_alloc();
    memset(actual, 0, SHA1_DIGEST_BYTES);

    sha1_start(ctx);
    for (onRepeat = 0; onRepeat < msgRepeats; onRepeat++) {
        add_single_message(ctx, msg, msgLen);
    }
    sha1_end(ctx, actual);

    TEST_ASSERT(memcmp(actual, digest, SHA1_DIGEST_BYTES) == 0);
    sha1_free_scrub(ctx);
}

static void add_single_message(struct sha1_ctx *ctx, const byte_t *msg,
                               size_t msgLen)
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
    byte_t *seed, *output;
    size_t seedLen, outputLen;

    hex_to_bytes(test->seed, &seed, &seedLen);
    hex_to_bytes(test->output, &output, &outputLen);
    ASSERT(seedLen == SHA1_DIGEST_BYTES, "Invalid seed size");
    ASSERT(outputLen == SHA1_DIGEST_BYTES, "Invalid output size");

    run_parsed_sha1_monte_test(seed, output);

    free(seed);
    free(output);
}

static void run_parsed_sha1_monte_test(const byte_t *seed,
                                       const byte_t *output)
{
    const int NIST_MONTE_OUTER_LOOP_SIZE = 100;
    struct sha1_ctx *ctx;
    const byte_t *seedJ;
    byte_t lastDigestJ[SHA1_DIGEST_BYTES];
    int j;

    ctx = sha1_alloc();
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
    seedJ = seed;

    /*
     * for ( j = 0 to 99 ):
     *     inner loop computes md[j][1002] from seed[j]
     *     seed[j+1] = md[j][1002]
     */
    for (j = 0; j < NIST_MONTE_OUTER_LOOP_SIZE; j++) {
        nist_monte_sha1_inner_loop(ctx, seedJ, lastDigestJ);
        seedJ = lastDigestJ;
    }

    /*
     * md[99][1002] is the expected output of the SHA-1 MCT.
     *
     * Note: in the SHAVS CAVP, each md[j][1002] is output as an intermediate
     * computation. Here, we check only the final result.
     */
    TEST_ASSERT(memcmp(lastDigestJ, output, SHA1_DIGEST_BYTES) == 0);
    sha1_free_scrub(ctx);
}

static void nist_monte_sha1_inner_loop(struct sha1_ctx *ctx,
                                       const byte_t *seedJ,
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
