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
#include "crypto/test/pi.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("BLAKE2b");

#define INCREMENTING_BYTES_00_3F_INCLUSIVE                                    \
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222" \
    "32425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"

#define INCREMENTING_BYTES_00_7F_INCLUSIVE                                    \
    INCREMENTING_BYTES_00_3F_INCLUSIVE                                        \
    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606"     \
    "162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"

#define INCREMENTING_BYTES_00_FE_INCLUSIVE                                    \
    INCREMENTING_BYTES_00_7F_INCLUSIVE                                        \
    "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A"     \
    "1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2"     \
    "C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E"     \
    "4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFE"

struct blake2b_kat {
    const char *msg;
    const char *key;
    const char *digest;
};

static void run_blake2b_selftest(void);
static void fill_selftest_seq(byte *out, size_t len, uint32_t seed);

static void run_blake2b_kat(const struct blake2b_kat *test);
static void add_long_blake2b(struct blake2b_ctx *ctx,
                             const struct bytearr *msg);

/*
 * The BLAKE2b official tests are taken from the BLAKE2b repository,
 * https://github.com/BLAKE2/BLAKE2/tree/master/testvectors (accessed
 * 26 July 2025). The blake2-kat.json file most closely matches the format
 * below.
 */
static const struct blake2b_kat official_tests[] = {
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
        .msg = INCREMENTING_BYTES_00_7F_INCLUSIVE,
        .key = "",
        .digest =
            "2319E3789C47E2DAA5FE807F61BEC2A1A6537FA03F19FF32E87EECBFD64B7E0E8"
            "CCFF439AC333B040F19B0C4DDD11A61E24AC1FE0F10A039806C5DCC0DA3D115",
    },

    /* Sub-two-block message, unkeyed */
    {
        .msg = INCREMENTING_BYTES_00_FE_INCLUSIVE,
        .key = "",
        .digest =
            "5B21C5FD8868367612474FA2E70E9CFA2201FFEEE8FAFAB5797AD58FEFA17C9B5"
            "B107DA4A3DB6320BAAF2C8617D5A51DF914AE88DA3867C2D41F0CC14FA67928",
    },

    /* Empty message, full-length key */
    {
        .msg = "",
        .key = INCREMENTING_BYTES_00_3F_INCLUSIVE,
        .digest =
            "10EBB67700B1868EFB4417987ACF4690AE9D972FB7A590C2F02871799AAA4786B"
            "5E996E8F0F4EB981FC214B005F42D2FF4233499391653DF7AEFCBC13FC51568",
    },

    /* One-byte message, full-length key */
    {
        .msg = "00",
        .key = INCREMENTING_BYTES_00_3F_INCLUSIVE,
        .digest =
            "961F6DD1E4DD30F63901690C512E78E4B45E4742ED197C3C5E45C549FD25F2E41"
            "87B0BC9FE30492B16B0D0BC4EF9B0F34C7003FAC09A5EF1532E69430234CEBD",
    },

    /* Single-block message, full-length key */
    {
        .msg = INCREMENTING_BYTES_00_7F_INCLUSIVE,
        .key = INCREMENTING_BYTES_00_3F_INCLUSIVE,
        .digest =
            "72065EE4DD91C2D8509FA1FC28A37C7FC9FA7D5B3F8AD3D0D7A25626B57B1B447"
            "88D4CAF806290425F9890A3A2A35A905AB4B37ACFD0DA6E4517B2525C9651E4",
    },

    /* Sub-two-block message, full-length key */
    {
        .msg = INCREMENTING_BYTES_00_FE_INCLUSIVE,
        .key = INCREMENTING_BYTES_00_3F_INCLUSIVE,
        .digest =
            "142709D62E28FCCCD0AF97FAD0F8465B971E82201DC51070FAA0372AA43E92484"
            "BE1C1E73BA10906D5D1853DB6A4106E0A7BF9800D373D6DEE2D46D62EF2A461",
    },
};

/*
 * Custom test vector, verified against two other independent implementations
 * of BLAKE2b:
 *
 * - OpenSSL 3.5.1 libcrypto implementation in C
 * - BouncyCastle 1.81 implementation in Java
 *
 * The key is half the maximum length, to test key padding. The message length
 * is 2.5-times the block size -- and the message will be split per
 * add_long_blake2b() --  to test all paths in blake2b_add() where buffers are
 * manipulated or the compression function f executed.
 */
static const struct blake2b_kat custom_tests[] = {
    {
        .msg = PI_FRACTIONAL_HEX_DIGITS_0_640,
        .key = PI_FRACTIONAL_HEX_DIGITS_640_704,
        .digest =
            "F4A536AD960D2467C444DA207983402C821882591D03E8CC8CE7642C455F8B81E"
            "4BE1AD2861BCE0D585E5B5DFE8C602854DCE972526AA37D111CF83D02AE6F2A",
    },
};

int main(void)
{
    size_t i;

    run_blake2b_selftest();

    for (i = 0; i < sizeof(official_tests) / sizeof(struct blake2b_kat); i++) {
        run_blake2b_kat(&official_tests[i]);
    }
    for (i = 0; i < sizeof(custom_tests) / sizeof(struct blake2b_kat); i++) {
        run_blake2b_kat(&(custom_tests[i]));
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
    struct blake2b_ctx *inner_ctx;
    size_t i, j, outlen, inlen;
    uint8_t in[1024], md[64], key[64];

    ctx = blake2b_alloc();
    inner_ctx = blake2b_alloc();
    blake2b_start(ctx, 32, NULL, 0);

    for (i = 0; i < 4; i++) {
        outlen = b2b_md_len[i];
        for (j = 0; j < 6; j++) {
            inlen = b2b_in_len[j];

            fill_selftest_seq(in, inlen, inlen);
            blake2b_single(inner_ctx, in, inlen, NULL, 0, md, outlen);
            blake2b_add(ctx, md, outlen);

            fill_selftest_seq(key, outlen, outlen);
            blake2b_single(inner_ctx, in, inlen, key, outlen, md, outlen);
            blake2b_add(ctx, md, outlen);
        }
    }

    blake2b_end(ctx, md);
    TEST_ASSERT(memcmp(md, blake2_res, sizeof(blake2_res)) == 0);

    blake2b_free_scrub(ctx);
    blake2b_free_scrub(inner_ctx);
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

static void run_blake2b_kat(const struct blake2b_kat *test)
{
    struct blake2b_ctx *ctx;
    struct bytearr key, msg, digest;
    byte actual[BLAKE2B_MAX_DIGEST_BYTES];

    hex_to_bytearr(&key, test->key);
    hex_to_bytearr(&msg, test->msg);
    hex_to_bytearr(&digest, test->digest);

    ASSERT(digest.len > 0 && digest.len <= 64,
           "Invalid BLAKE2b digest length (%zu)", digest.len);
    ASSERT(key.len <= 64, "Invalid BLAKE2b key length (%zu)", key.len);

    ctx = blake2b_alloc();
    memset(actual, 0, digest.len);

    blake2b_start(ctx, digest.len, key.bytes, key.len);
    add_long_blake2b(ctx, &msg);
    blake2b_end(ctx, actual);

    TEST_ASSERT(memcmp(actual, digest.bytes, digest.len) == 0);
    blake2b_free_scrub(ctx);
}

static void add_long_blake2b(struct blake2b_ctx *ctx,
                             const struct bytearr *msg)
{
    /*
     * If the message is larger than one block in size, it will be broken up
     * and added in three pieces, to test the functionality of adding partial
     * blocks to the context.
     */
    const size_t quarter_block_len = BLAKE2B_BLOCK_BYTES / 4;

    if (msg->len <= BLAKE2B_BLOCK_BYTES) {
        blake2b_add(ctx, msg->bytes, msg->len);
    }
    else {
        blake2b_add(ctx, msg->bytes, quarter_block_len);
        blake2b_add(ctx, msg->bytes + quarter_block_len,
                    msg->len - 2 * quarter_block_len);
        blake2b_add(ctx, msg->bytes + msg->len - quarter_block_len,
                    quarter_block_len);
    }
}
