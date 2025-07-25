/*
 * Copyright (c) 2025 Ryan Vogt <rvogt.ca@gmail.com>
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
#include "crypto/primitives/blake2b/blake2b.h"
#include "crypto/test/framework.h"
#include "crypto/test/hex.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("BLAKE2b");

struct blake2b_plain_test {
    const char *msg;
    const char *key;
    const char *digest;
};

static void run_blake2b_selftest(void);
static void fill_selftest_seq(byte *out, size_t len, uint32_t seed);
static void blake2b_single(byte *digest, size_t digest_len, const byte *key,
                           size_t key_len, const byte *msg, size_t msg_len);

static void run_blake2b_plain_test(const struct blake2b_plain_test *test);
static void run_parsed_blake2b_plain_test(const byte *msg, size_t msg_len,
                                          const byte *key, size_t key_len,
                                          const byte *digest,
                                          size_t digest_len);
static void add_single_message(struct blake2b_ctx *ctx, const byte *msg,
                               size_t msg_len);

static void parse_hex_to_bytes(const char *msg_hex, byte **msg_bytes,
                               size_t *msg_len, const char *key_hex,
                               byte **key_bytes, size_t *key_len,
                               const char *digest_hex, byte **digest_bytes,
                               size_t *digest_len);

/*
 * All BLAKE2b plain tests are taken from the BLAKE2b official repository,
 * blake2-kat.json. Partial-block keys test both that keying and padding the
 * key work correctly.
 */
static const struct blake2b_plain_test blake2b_plain_tests[] = {
    /* Empty message, unkeyed */
    {
        .msg = "",
        .key = "",
        .digest =
            "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D"
            "25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE",
    },

    /* One-byte message, unkeyed */
    {
        .msg = "00",
        .key = "",
        .digest =
            "2FA3F686DF876995167E7C2E5D74C4C7B6E48F8068FE0E44208344D480F7904C3"
            "6963E44115FE3EB2A3AC8694C28BCB4F5A0F3276F2E79487D8219057A506E4B",
    },

    /* Single-block message, unkeyed */
    {
        .msg =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40"
            "4142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606"
            "162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        .key = "",
        .digest =
            "2319E3789C47E2DAA5FE807F61BEC2A1A6537FA03F19FF32E87EECBFD64B7E0E8"
            "CCFF439AC333B040F19B0C4DDD11A61E24AC1FE0F10A039806C5DCC0DA3D115",
    },

    /* Sub-two-block message, unkeyed */
    {
        .msg =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40"
            "4142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606"
            "162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F8081"
            "82838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A"
            "2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2"
            "C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E"
            "3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFE",
        .key = "",
        .digest =
            "5B21C5FD8868367612474FA2E70E9CFA2201FFEEE8FAFAB5797AD58FEFA17C9B5"
            "B107DA4A3DB6320BAAF2C8617D5A51DF914AE88DA3867C2D41F0CC14FA67928",
    },

    /* Empty message, half-block key */
    {
        .msg = "",
        .key =
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2"
            "02122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        .digest =
            "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b"
            "5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
    },

    /* One-byte message, half-block key */
    {
        .msg = "00",
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .digest =
            "961F6DD1E4DD30F63901690C512E78E4B45E4742ED197C3C5E45C549FD25F2E41"
            "87B0BC9FE30492B16B0D0BC4EF9B0F34C7003FAC09A5EF1532E69430234CEBD",
    },

    /* Single-block message, half-block key */
    {
        .msg =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40"
            "4142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606"
            "162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .digest =
            "72065EE4DD91C2D8509FA1FC28A37C7FC9FA7D5B3F8AD3D0D7A25626B57B1B447"
            "88D4CAF806290425F9890A3A2A35A905AB4B37ACFD0DA6E4517B2525C9651E4",
    },

    /* Sub-two-block message, half-block key */
    {
        .msg =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40"
            "4142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606"
            "162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F8081"
            "82838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A"
            "2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2"
            "C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E"
            "3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFE",
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .digest =
            "142709D62E28FCCCD0AF97FAD0F8465B971E82201DC51070FAA0372AA43E92484"
            "BE1C1E73BA10906D5D1853DB6A4106E0A7BF9800D373D6DEE2D46D62EF2A461",
    },
};

int main(void)
{
    size_t i;
    size_t num_plain_tests;

    run_blake2b_selftest();

    num_plain_tests =
        sizeof(blake2b_plain_tests) / sizeof(struct blake2b_plain_test);
    for (i = 0; i < num_plain_tests; i++) {
        run_blake2b_plain_test(&blake2b_plain_tests[i]);
    }

    TEST_CONCLUDE();
    return 0;
}

static void run_blake2b_selftest(void)
{
    /* Adapted from RFC 7693, Appendix E */
    const byte blake2_res[32] = {
        0xC2, 0x3A, 0x78, 0x00, 0xD9, 0x81, 0x23, 0xBD, 0x10, 0xF5, 0x06,
        0xC6, 0x1E, 0x29, 0xDA, 0x56, 0x03, 0xD7, 0x63, 0xB8, 0xBB, 0xAD,
        0x2E, 0x73, 0x7F, 0x5E, 0x76, 0x5A, 0x7B, 0xCC, 0xD4, 0x75};
    const size_t b2b_md_len[4] = {20, 32, 48, 64};
    const size_t b2b_in_len[6] = {0, 3, 128, 129, 255, 1024};

    struct blake2b_ctx *ctx;
    size_t i, j, outlen, inlen;
    uint8_t in[1024], md[64], key[64];

    ctx = blake2b_alloc();
    blake2b_start(ctx, 32, NULL, 0);

    for (i = 0; i < 4; i++) {
        outlen = b2b_md_len[i];
        for (j = 0; j < 6; j++) {
            inlen = b2b_in_len[j];

            fill_selftest_seq(in, inlen, inlen);
            blake2b_single(md, outlen, NULL, 0, in, inlen);
            blake2b_add(ctx, md, outlen);

            fill_selftest_seq(key, outlen, outlen);
            blake2b_single(md, outlen, key, outlen, in, inlen);
            blake2b_add(ctx, md, outlen);
        }
    }

    blake2b_end(ctx, md);
    TEST_ASSERT(memcmp(md, blake2_res, sizeof(blake2_res)) == 0);

    blake2b_free_scrub(ctx);
}

static void fill_selftest_seq(byte *out, size_t len, uint32_t seed)
{
    /* From RFC 7693, Appendix E */
    size_t i;
    uint32_t t, a, b;

    a = 0xDEAD4BAD * seed;
    b = 1;

    for (i = 0; i < len; i++) {
        t = a + b;
        a = b;
        b = t;
        out[i] = (t >> 24) & 0xFF;
    }
}

static void blake2b_single(byte *digest, size_t digest_len, const byte *key,
                           size_t key_len, const byte *msg, size_t msg_len)
{
    struct blake2b_ctx *ctx;

    ctx = blake2b_alloc();

    blake2b_start(ctx, digest_len, key, key_len);
    blake2b_add(ctx, msg, msg_len);
    blake2b_end(ctx, digest);

    blake2b_free_scrub(ctx);
}

static void run_blake2b_plain_test(const struct blake2b_plain_test *test)
{
    byte *msg, *key, *digest;
    size_t msg_len, key_len, digest_len;

    parse_hex_to_bytes(test->msg, &msg, &msg_len, test->key, &key, &key_len,
                       test->digest, &digest, &digest_len);
    run_parsed_blake2b_plain_test(msg, msg_len, key, key_len, digest,
                                  digest_len);

    free(msg);
    free(key);
    free(digest);
}

static void run_parsed_blake2b_plain_test(const byte *msg, size_t msg_len,
                                          const byte *key, size_t key_len,
                                          const byte *digest,
                                          size_t digest_len)
{
    struct blake2b_ctx *ctx;
    byte actual[BLAKE2B_MAX_DIGEST_BYTES];

    ctx = blake2b_alloc();
    memset(actual, 0, digest_len);

    blake2b_start(ctx, digest_len, key, key_len);
    add_single_message(ctx, msg, msg_len);
    blake2b_end(ctx, actual);

    TEST_ASSERT(memcmp(actual, digest, digest_len) == 0);
    blake2b_free_scrub(ctx);
}

static void add_single_message(struct blake2b_ctx *ctx, const byte *msg,
                               size_t msg_len)
{
    /*
     * If the message is larger than one block in size, it will be broken up
     * and added in three pieces, to test the functionality of adding partial
     * blocks to the context.
     */
    const size_t quarter_block_len = BLAKE2B_BLOCK_BYTES / 4;

    if (msg_len <= BLAKE2B_BLOCK_BYTES) {
        blake2b_add(ctx, msg, msg_len);
    }
    else {
        blake2b_add(ctx, msg, quarter_block_len);
        blake2b_add(ctx, msg + quarter_block_len,
                    msg_len - 2 * quarter_block_len);
        blake2b_add(ctx, msg + msg_len - quarter_block_len, quarter_block_len);
    }
}

static void parse_hex_to_bytes(const char *msg_hex, byte **msg_bytes,
                               size_t *msg_len, const char *key_hex,
                               byte **key_bytes, size_t *key_len,
                               const char *digest_hex, byte **digest_bytes,
                               size_t *digest_len)
{
    hex_to_bytes(msg_hex, msg_bytes, msg_len);
    hex_to_bytes(key_hex, key_bytes, key_len);
    hex_to_bytes(digest_hex, digest_bytes, digest_len);

    ASSERT(*digest_len > 0 && *digest_len <= 64,
           "Invalid BLAKE2b digest length");
    ASSERT(*key_len <= 64, "Invalid BLAKE2b key length");
}
