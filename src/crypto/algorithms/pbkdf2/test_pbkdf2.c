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
#include "crypto/abstract/chf.h"
#include "crypto/algorithms/pbkdf2/pbkdf2.h"
#include "crypto/test/framework.h"

#include <string.h>

TEST_PREAMBLE("PBKDF2");

/*
 * Test an execution of PBKDF2 SHA-1 where the derived key is the length of the
 * hash output, and only a single iteration is used.
 *
 * Expected results are from RFC 6070, P with 8 octets, S with 4 octets, c=1,
 * dkLen=20.
 */
static void test_single_cycle(void)
{
    const byte_t password[] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64};
    const byte_t salt[] = {0x73, 0x61, 0x6C, 0x74};
    const unsigned int c = 1;
    const byte_t expected[] = {0x0C, 0x60, 0xC8, 0x0F, 0x96, 0x1F, 0x0E,
                               0x71, 0xF3, 0xA9, 0xB5, 0x24, 0xAF, 0x60,
                               0x12, 0x06, 0x2F, 0xE0, 0x37, 0xA6};
    byte_t actual[sizeof(expected)];

    memset(actual, 0, sizeof(actual));
    pbkdf2_hmac(actual, sizeof(actual), (const char *)password,
                sizeof(password), salt, sizeof(salt), c, CHF_ALG_SHA1);
    TEST_ASSERT(memcmp(actual, expected, sizeof(expected)) == 0);
}

/*
 * Test an execution of PBKDF2 SHA-1 where the derived key is the length of the
 * hash output, and multiple iterations are used.
 *
 * Expected results are from RFC 6070, P with 8 octets, S with 4 octets,
 * c=4096, dkLen=20.
 */
static void test_multiple_cycles(void)
{
    const byte_t password[] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64};
    const byte_t salt[] = {0x73, 0x61, 0x6C, 0x74};
    const unsigned int c = 4096;
    const byte_t expected[] = {0x4B, 0x00, 0x79, 0x01, 0xB7, 0x65, 0x48,
                               0x9A, 0xBE, 0xAD, 0x49, 0xD9, 0x26, 0xF7,
                               0x21, 0xD0, 0x65, 0xA4, 0x29, 0xC1};
    byte_t actual[sizeof(expected)];

    memset(actual, 0, sizeof(actual));
    pbkdf2_hmac(actual, sizeof(actual), (const char *)password,
                sizeof(password), salt, sizeof(salt), c, CHF_ALG_SHA1);
    TEST_ASSERT(memcmp(actual, expected, sizeof(expected)) == 0);
}

/*
 * Test an execution of PBKDF2 SHA-1 where the derived key is shorter than the
 * length of the hash output, and multiple iterations are used.
 *
 * Expected results are from RFC 6070, P with 9 octets, S with 5 octets,
 * c=4096, dkLen=16.
 */
static void test_dk_shorter_than_hlen(void)
{
    const byte_t password[] = {0x70, 0x61, 0x73, 0x73, 0x00,
                               0x77, 0x6F, 0x72, 0x64};
    const byte_t salt[] = {0x73, 0x61, 0x00, 0x6C, 0x74};
    const unsigned int c = 4096;
    const byte_t expected[] = {0x56, 0xFA, 0x6A, 0xA7, 0x55, 0x48, 0x09, 0x9D,
                               0xCC, 0x37, 0xD7, 0xF0, 0x34, 0x25, 0xE0, 0xC3};
    byte_t actual[sizeof(expected)];

    memset(actual, 0, sizeof(actual));
    pbkdf2_hmac(actual, sizeof(actual), (const char *)password,
                sizeof(password), salt, sizeof(salt), c, CHF_ALG_SHA1);
    TEST_ASSERT(memcmp(actual, expected, sizeof(expected)) == 0);
}

/*
 * Test an execution of PBKDF2 SHA-1 where the derived key is longer than the
 * length of the hash output, and multiple iterations are used.
 *
 * Expected results are from RFC 6070, P with 24 octets, S with 36 octets,
 * c=4096, dkLen=25.
 */
static void test_dk_larger_than_hlen(void)
{
    const byte_t password[] = {0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64,
                               0x50, 0x41, 0x53, 0x53, 0x57, 0x4F, 0x52, 0x44,
                               0x70, 0x61, 0x73, 0x73, 0x77, 0x6F, 0x72, 0x64};
    const byte_t salt[] = {0x73, 0x61, 0x6C, 0x74, 0x53, 0x41, 0x4C, 0x54,
                           0x73, 0x61, 0x6C, 0x74, 0x53, 0x41, 0x4C, 0x54,
                           0x73, 0x61, 0x6C, 0x74, 0x53, 0x41, 0x4C, 0x54,
                           0x73, 0x61, 0x6C, 0x74, 0x53, 0x41, 0x4C, 0x54,
                           0x73, 0x61, 0x6C, 0x74};
    const unsigned int c = 4096;
    const byte_t expected[] = {0x3D, 0x2E, 0xEC, 0x4F, 0xE4, 0x1C, 0x84,
                               0x9B, 0x80, 0xC8, 0xD8, 0x36, 0x62, 0xC0,
                               0xE4, 0x4A, 0x8B, 0x29, 0x1A, 0x96, 0x4C,
                               0xF2, 0xF0, 0x70, 0x38};
    byte_t actual[sizeof(expected)];

    memset(actual, 0, sizeof(actual));
    pbkdf2_hmac(actual, sizeof(actual), (const char *)password,
                sizeof(password), salt, sizeof(salt), c, CHF_ALG_SHA1);
    TEST_ASSERT(memcmp(actual, expected, sizeof(expected)) == 0);
}

/*
 * Run the PBKDF2 tests and report the success rate.
 */
int main()
{
    test_single_cycle();
    test_multiple_cycles();
    test_dk_shorter_than_hlen();
    test_dk_larger_than_hlen();
    TEST_CONCLUDE();
}
