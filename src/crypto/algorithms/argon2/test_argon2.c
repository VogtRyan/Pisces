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
#include "crypto/algorithms/argon2/argon2.h"
#include "crypto/test/framework.h"
#include "crypto/test/hex.h"
#include "crypto/test/pi.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("Argon2");

#define RFC_KAT_PASSWORD                                                      \
    "0101010101010101010101010101010101010101010101010101010101010101"
#define RFC_KAT_SALT         "02020202020202020202020202020202"
#define RFC_KAT_K_SECRET     "0303030303030303"
#define RFC_KAT_X_ASSOCIATED "040404040404040404040404"

struct argon2_kat {
    argon2_variant y_variant;
    size_t m_memsize_kb;
    unsigned int p_parallelism;
    unsigned int t_passes;
    const char *password;
    const char *salt;
    const char *k_secret;
    const char *x_associated;
    const char *derived_key;
};

static void run_ar2kat(const struct argon2_kat *test);
static void run_parsed_ar2kat(const struct argon2_kat *test,
                              const char *password, size_t password_len,
                              const byte *salt, size_t salt_len,
                              const byte *k_secret, size_t k_secret_len,
                              const byte *x_associated,
                              size_t x_associated_len, const byte *derived_key,
                              size_t derived_key_len, bool multithread);

static const struct argon2_kat rfc_kats[] = {
    /* RFC 9106, section 5.1 (Argon2d) */
    {
        .y_variant = ARGON2_VARIANT_D,
        .m_memsize_kb = 32,
        .p_parallelism = 4,
        .t_passes = 3,
        .password = RFC_KAT_PASSWORD,
        .salt = RFC_KAT_SALT,
        .k_secret = RFC_KAT_K_SECRET,
        .x_associated = RFC_KAT_X_ASSOCIATED,
        .derived_key =
            "512B391B6F1162975371D30919734294F868E3BE3984F3C1A13A4DB9FABE4ACB",
    },

    /* RFC 9106, section 5.2 (Argon2i) */
    {
        .y_variant = ARGON2_VARIANT_I,
        .m_memsize_kb = 32,
        .p_parallelism = 4,
        .t_passes = 3,
        .password = RFC_KAT_PASSWORD,
        .salt = RFC_KAT_SALT,
        .k_secret = RFC_KAT_K_SECRET,
        .x_associated = RFC_KAT_X_ASSOCIATED,
        .derived_key =
            "C814D9D1DC7F37AA13F0D77F2494BDA1C8DE6B016DD388D29952A4C4672B6CE8",
    },

    /* RFC 9106, section 5.3 (Argon2id) */
    {
        .y_variant = ARGON2_VARIANT_ID,
        .m_memsize_kb = 32,
        .p_parallelism = 4,
        .t_passes = 3,
        .password = RFC_KAT_PASSWORD,
        .salt = RFC_KAT_SALT,
        .k_secret = RFC_KAT_K_SECRET,
        .x_associated = RFC_KAT_X_ASSOCIATED,
        .derived_key =
            "0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659",
    },
};

/*
 * Custom test vectors, verified against two other independent implementations
 * of Argon2 (except for the empty-salt vectors; details below):
 *
 * - OpenSSL 3.5.1 libcrypto implementation in C
 * - BouncyCastle 1.81 implementation in Java
 *
 * A. Minimal valid input vectors for Argon2d, Argon2i, and Argon2id, which
 *    have an empty salt. An empty salt is explicitly supported by RFC 9106
 *    (see section 3.2, step 1). But, an empty salt is supported by neither
 *    OpenSSL's libcrypto implementation nor the Argon2 reference imlementation
 *    (both of which enforce an arbitrary minimum salt length of 8 bytes). So
 *    these three specific vectors were verified against only the BouncyCastle
 *    implementation.
 *
 * B. Minimal valid widely supported input vectors. These vectors are
 *    identical to those above, but with 8-byte salts.
 *
 * C. Vectors for Argon2id, both with and without the optional K and X values,
 *    using random data as input. These vectors are meant to represent a
 *    typical use case.
 *
 * D. A vector for Argon2id where m != m' (which affects the computation of
 *    the H_0 pre-hashing digest). That is, m is not divisible by p * q = 4p.
 */
static const struct argon2_kat custom_kats[] = {
    /* Minimum valid input to Argon2d as specified by RFC 9106 */
    {
        .y_variant = ARGON2_VARIANT_D,
        .m_memsize_kb = 8,
        .p_parallelism = 1,
        .t_passes = 1,
        .password = "00000000",
        .salt = "",
        .k_secret = "",
        .x_associated = "",
        .derived_key = "774802AC7355FE0E4A157901626FE33B",
    },

    /* Minimum valid input to Argon2i as specified by RFC 9106 */
    {
        .y_variant = ARGON2_VARIANT_I,
        .m_memsize_kb = 8,
        .p_parallelism = 1,
        .t_passes = 1,
        .password = "00000000",
        .salt = "",
        .k_secret = "",
        .x_associated = "",
        .derived_key = "9D97FE92CDFB708CACDA05A9C9DFAB38",
    },

    /* Minimum valid input to Argon2id as specified by RFC 9106 */
    {
        .y_variant = ARGON2_VARIANT_ID,
        .m_memsize_kb = 8,
        .p_parallelism = 1,
        .t_passes = 1,
        .password = "00000000",
        .salt = "",
        .k_secret = "",
        .x_associated = "",
        .derived_key = "3E17025A4497976EDB69A49B3DF14684",
    },

    /* Minimum widely supported valid input to Argon2d */
    {
        .y_variant = ARGON2_VARIANT_D,
        .m_memsize_kb = 8,
        .p_parallelism = 1,
        .t_passes = 1,
        .password = "00000000",
        .salt = "0000000000000000",
        .k_secret = "",
        .x_associated = "",
        .derived_key = "4E87B02089C24067C72051BF3A134506",
    },

    /* Minimum widely supported valid input to Argon2i */
    {
        .y_variant = ARGON2_VARIANT_I,
        .m_memsize_kb = 8,
        .p_parallelism = 1,
        .t_passes = 1,
        .password = "00000000",
        .salt = "0000000000000000",
        .k_secret = "",
        .x_associated = "",
        .derived_key = "466A443F74831BE59F70521D5BE528EA",
    },

    /* Minimum widely supported valid input to Argon2id */
    {
        .y_variant = ARGON2_VARIANT_ID,
        .m_memsize_kb = 8,
        .p_parallelism = 1,
        .t_passes = 1,
        .password = "00000000",
        .salt = "0000000000000000",
        .k_secret = "",
        .x_associated = "",
        .derived_key = "6D5CC9F518AEA982D53128CD03BBA3C6",
    },

    /* Random input without K and X values */
    {
        .y_variant = ARGON2_VARIANT_ID,
        .m_memsize_kb = 32,
        .p_parallelism = 4,
        .t_passes = 3,
        .password = PI_FRACTIONAL_HEX_DIGITS_0_64,
        .salt = PI_FRACTIONAL_HEX_DIGITS_64_96,
        .k_secret = "",
        .x_associated = "",
        .derived_key =
            "EE798CC2C25315608F8395A99B64AA2898A7E922BA612E51693141BB11C74BF7",
    },

    /* Random input with K and X values */
    {
        .y_variant = ARGON2_VARIANT_ID,
        .m_memsize_kb = 32,
        .p_parallelism = 4,
        .t_passes = 3,
        .password = PI_FRACTIONAL_HEX_DIGITS_0_64,
        .salt = PI_FRACTIONAL_HEX_DIGITS_64_96,
        .k_secret = PI_FRACTIONAL_HEX_DIGITS_96_128,
        .x_associated = PI_FRACTIONAL_HEX_DIGITS_128_160,
        .derived_key =
            "1443FB908564B3836DA6BB1FE097F1749A1E6FC9F78E9F5C637985FB4273B972",
    },

    /* Random input where m != m' */
    {
        .y_variant = ARGON2_VARIANT_ID,
        .m_memsize_kb = 37,
        .p_parallelism = 4,
        .t_passes = 3,
        .password = PI_FRACTIONAL_HEX_DIGITS_0_64,
        .salt = PI_FRACTIONAL_HEX_DIGITS_64_96,
        .k_secret = PI_FRACTIONAL_HEX_DIGITS_96_128,
        .x_associated = PI_FRACTIONAL_HEX_DIGITS_128_160,
        .derived_key =
            "96E3FD9B09E84510DF4FA19AA13C248FAA96BC041289FDF07BC091642F7FDE12",
    },
};

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(rfc_kats) / sizeof(struct argon2_kat); i++) {
        run_ar2kat(&rfc_kats[i]);
    }
    for (i = 0; i < sizeof(custom_kats) / sizeof(struct argon2_kat); i++) {
        run_ar2kat(&custom_kats[i]);
    }

    TEST_CONCLUDE();
}

static void run_ar2kat(const struct argon2_kat *test)
{
    byte *password, *salt, *k_secret, *x_associated, *derived_key;
    size_t password_len, salt_len, k_secret_len, x_associated_len,
        derived_key_len;

    hex_to_bytes(test->password, &password, &password_len);
    hex_to_bytes(test->salt, &salt, &salt_len);
    hex_to_bytes(test->k_secret, &k_secret, &k_secret_len);
    hex_to_bytes(test->x_associated, &x_associated, &x_associated_len);
    hex_to_bytes(test->derived_key, &derived_key, &derived_key_len);

    run_parsed_ar2kat(test, (const char *)password, password_len, salt,
                      salt_len, k_secret, k_secret_len, x_associated,
                      x_associated_len, derived_key, derived_key_len, false);

#ifndef PISCES_NO_MULTITHREAD
    if (test->p_parallelism > 1) {
        run_parsed_ar2kat(test, (const char *)password, password_len, salt,
                          salt_len, k_secret, k_secret_len, x_associated,
                          x_associated_len, derived_key, derived_key_len,
                          true);
    }
#endif

    free(password);
    free(salt);
    free(k_secret);
    free(x_associated);
    free(derived_key);
}

static void run_parsed_ar2kat(const struct argon2_kat *test,
                              const char *password, size_t password_len,
                              const byte *salt, size_t salt_len,
                              const byte *k_secret, size_t k_secret_len,
                              const byte *x_associated,
                              size_t x_associated_len, const byte *derived_key,
                              size_t derived_key_len, bool multithread)
{
    struct argon2_ctx *ctx;
    byte *actual;
    size_t max_threads;

    actual = (byte *)calloc(derived_key_len, 1);
    GUARD_ALLOC(actual);

    if (multithread) {
        max_threads = ARGON2_MAX_THREADS_AUTO;
    }
    else {
        max_threads = ARGON2_MAX_THREADS_SINGLE;
    }

    ctx = argon2_alloc(test->y_variant, test->m_memsize_kb,
                       test->p_parallelism, test->t_passes, max_threads);
    argon2_derive_opt(ctx, actual, derived_key_len, password, password_len,
                      salt, salt_len, k_secret, k_secret_len, x_associated,
                      x_associated_len);
    TEST_ASSERT(memcmp(actual, derived_key, derived_key_len) == 0);

    argon2_free_scrub(ctx);
    free(actual);
}
