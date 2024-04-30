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
#include "crypto/abstract/chf.h"
#include "crypto/algorithms/pbkdf2/pbkdf2.h"
#include "crypto/test/framework.h"
#include "crypto/test/hex.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("PBKDF2");

/*
 * Parameters for testing the output of a single invocation of the PBKDF2
 * algorithm.
 */
struct pbkdf2_test {
    chf_algorithm_t hashAlg;
    unsigned int iterationCount;
    const char *password;
    const char *salt;
    const char *derivedKey;
};

/*
 * Runs a PBKDF2 test, and asserts that the actual derived key matches the
 * expected derived key in the given test parameters.
 */
static void run_pbkdf2_test(const struct pbkdf2_test *test);

/*
 * Runs a PBKDF2 test that has been parsed from its hexadecimal string format.
 */
static void run_parsed_pbkdf2_test(chf_algorithm_t hashAlg,
                                   unsigned int iterationCount,
                                   const byte_t *password, size_t passwordLen,
                                   const byte_t *salt, size_t saltLen,
                                   const byte_t *derivedKey,
                                   size_t derivedKeyLen);

/*
 * All of the official tests (from RFC 6070) to run for PBKDF2. The fourth test
 * vector, with an iteration count of 16777216, is intentionally omitted
 * because of the time it takes to run.
 */
#define RUN_RFC_6070_TEST_VECTOR_FOUR (0)
static const struct pbkdf2_test allTests[] = {
    /* RFC 6070, first test vector, with P="password" and S="salt" */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 1,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derivedKey = "0C60C80F961F0E71F3A9B524AF6012062FE037A6",
    },

    /* RFC 6070, second test vector, with P="password" and S="salt" */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 2,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derivedKey = "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957",
    },

    /* RFC 6070, third test vector, with P="password" and S="salt" */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 4096,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derivedKey = "4B007901B765489ABEAD49D926F721D065A429C1",
    },

#if RUN_RFC_6070_TEST_VECTOR_FOUR
    /*
     * RFC 6070, fourth test vector, with P="password" and S="salt", and a very
     * high iteration count.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 16777216,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derivedKey = "EEFE3D61CD4DA4E4E9945B3D6BA2158C2634E984",
    },
#endif /* RUN_RFC_6070_TEST_VECTOR_FOUR */

    /*
     * RFC 6070, fifth test vector, with P="passwordPASSWORDpassword" and
     * S="saltSALTsaltSALTsaltSALTsaltSALTsalt".
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 4096,
        .password = "70617373776F726450415353574F524470617373776F7264",
        .salt = "73616C7453414C5473616C7453414C5473616C7453414C5473616C7453414"
                "C5473616C74",
        .derivedKey = "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038",
    },

    /* RFC 6070, sixth test vector, with P="pass\0word" and S="sa\0lt" */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 4096,
        .password = "7061737300776F7264",
        .salt = "7361006C74",
        .derivedKey = "56FA6AA75548099DCC37D7F03425E0C3",
    },
};

/*
 * Run the PBKDF2 tests and report the success rate.
 */
int main()
{
    size_t onTest;

    for (onTest = 0; onTest < sizeof(allTests) / sizeof(struct pbkdf2_test);
         onTest++) {
        run_pbkdf2_test(&allTests[onTest]);
    }

    TEST_CONCLUDE();
}

static void run_pbkdf2_test(const struct pbkdf2_test *test)
{
    byte_t *password, *salt, *derivedKey;
    size_t passwordLen, saltLen, derivedKeyLen;

    hex_to_bytes(test->password, &password, &passwordLen);
    hex_to_bytes(test->salt, &salt, &saltLen);
    hex_to_bytes(test->derivedKey, &derivedKey, &derivedKeyLen);

    run_parsed_pbkdf2_test(test->hashAlg, test->iterationCount, password,
                           passwordLen, salt, saltLen, derivedKey,
                           derivedKeyLen);

    free(password);
    free(salt);
    free(derivedKey);
}

static void run_parsed_pbkdf2_test(chf_algorithm_t hashAlg,
                                   unsigned int iterationCount,
                                   const byte_t *password, size_t passwordLen,
                                   const byte_t *salt, size_t saltLen,
                                   const byte_t *derivedKey,
                                   size_t derivedKeyLen)
{
    byte_t *actual;
    actual = calloc(1, derivedKeyLen);
    ASSERT_ALLOC(actual);

    pbkdf2_hmac(actual, derivedKeyLen, (const char *)password, passwordLen,
                salt, saltLen, iterationCount, hashAlg);

    TEST_ASSERT(memcmp(actual, derivedKey, derivedKeyLen) == 0);
    free(actual);
}
