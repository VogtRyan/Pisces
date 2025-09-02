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

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("Argon2");

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

static const struct argon2_kat kats[] = {
    /* RFC 9106, section 5.1 (Argon2d) */
    {
        .y_variant = ARGON2_VARIANT_D,
        .m_memsize_kb = 32,
        .p_parallelism = 4,
        .t_passes = 3,
        .password =
            "0101010101010101010101010101010101010101010101010101010101010101",
        .salt = "02020202020202020202020202020202",
        .k_secret = "0303030303030303",
        .x_associated = "040404040404040404040404",
        .derived_key =
            "512B391B6F1162975371D30919734294F868E3BE3984F3C1A13A4DB9FABE4ACB",
    },

    /* RFC 9106, section 5.2 (Argon2i) */
    {
        .y_variant = ARGON2_VARIANT_I,
        .m_memsize_kb = 32,
        .p_parallelism = 4,
        .t_passes = 3,
        .password =
            "0101010101010101010101010101010101010101010101010101010101010101",
        .salt = "02020202020202020202020202020202",
        .k_secret = "0303030303030303",
        .x_associated = "040404040404040404040404",
        .derived_key =
            "C814D9D1DC7F37AA13F0D77F2494BDA1C8DE6B016DD388D29952A4C4672B6CE8",
    },

    /* RFC 9106, section 5.3 (Argon2id) */
    {
        .y_variant = ARGON2_VARIANT_ID,
        .m_memsize_kb = 32,
        .p_parallelism = 4,
        .t_passes = 3,
        .password =
            "0101010101010101010101010101010101010101010101010101010101010101",
        .salt = "02020202020202020202020202020202",
        .k_secret = "0303030303030303",
        .x_associated = "040404040404040404040404",
        .derived_key =
            "0D640DF58D78766C08C037A34A8B53C9D01EF0452D75B65EB52520E96B01E659",
    },
};

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(kats) / sizeof(struct argon2_kat); i++) {
        run_ar2kat(&kats[i]);
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
    run_parsed_ar2kat(test, (const char *)password, password_len, salt,
                      salt_len, k_secret, k_secret_len, x_associated,
                      x_associated_len, derived_key, derived_key_len, true);
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
