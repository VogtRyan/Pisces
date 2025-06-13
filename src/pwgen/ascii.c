/*
 * Copyright (c) 2008-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "ascii.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/cprng.h"

#include <math.h>
#include <stddef.h>

void generate_pwd_ascii(char *pwd, size_t pwdlen)
{
    struct cprng *rng;
    size_t gen_size, gen_size_max, i;
    byte *rand_buf;

    gen_size_max = pwdlen;
    rand_buf = (byte *)malloc(gen_size_max);
    GUARD_ALLOC(rand_buf);
    rng = cprng_alloc_default();

    /*
     * There are 94 legal characters (ASCII 33 to 126; space at 32 is omitted),
     * so we can use 94*2 = 188/256 possible bytes values to generate an
     * unbiased character.
     */
    while (pwdlen > 0) {
        gen_size = pwdlen;
        cprng_bytes(rng, rand_buf, gen_size);
        for (i = 0; i < gen_size; i++) {
            if (rand_buf[i] < 188) {
                *pwd = (char)((int)rand_buf[i] % 94 + 33);
                pwdlen--;
                pwd++;
            }
        }
    }

    cprng_free_scrub(rng);
    scrub_memory(rand_buf, gen_size_max);
    free(rand_buf);
}

double bits_security_ascii(size_t pwdlen)
{
    /* log_2(94^n) == n * log_2(94) */
    return pwdlen * log2(94);
}

void generate_pwd_alpha_num(char *pwd, size_t pwdlen)
{
    struct cprng *rng;
    size_t gen_size, gen_size_max, i;
    byte *rand_buf;

    gen_size_max = pwdlen;
    rand_buf = (byte *)malloc(gen_size_max);
    GUARD_ALLOC(rand_buf);
    rng = cprng_alloc_default();

    /*
     * There are 62 legal characters (26 + 26 + 10), we can use 62*4 = 248/256
     * possible byte values to generate an unbiased character.
     */
    while (pwdlen > 0) {
        gen_size = pwdlen;
        cprng_bytes(rng, rand_buf, gen_size);
        for (i = 0; i < gen_size; i++) {
            if (rand_buf[i] >= 248) {
                continue;
            }
            if (rand_buf[i] < 104) {
                /* Lower case letters */
                *pwd = (char)((int)rand_buf[i] % 26 + 97);
            }
            else if (rand_buf[i] < 208) {
                /* Upper case letters */
                *pwd = (char)((int)rand_buf[i] % 26 + 65);
            }
            else {
                /* Numbers */
                *pwd = (char)((int)rand_buf[i] % 10 + 48);
            }
            pwdlen--;
            pwd++;
        }
    }

    cprng_free_scrub(rng);
    scrub_memory(rand_buf, gen_size_max);
    free(rand_buf);
}

double bits_security_alpha_num(size_t pwdlen)
{
    /* log_2(62^n) == n * log_2(62) */
    return pwdlen * log2(62);
}

void generate_pwd_numeric(char *pwd, size_t pwdlen)
{
    struct cprng *rng;
    size_t gen_size, gen_size_max, i;
    byte *rand_buf;

    /* We can potentially extract two digits from each random byte */
    gen_size_max = pwdlen / 2;
    if (pwdlen & 0x1) {
        gen_size_max++;
    }
    rand_buf = (byte *)malloc(gen_size_max);
    GUARD_ALLOC(rand_buf);
    rng = cprng_alloc_default();

    /*
     * If any random byte is in the range [0, 199], we can extract two unbiased
     * digits from it. One approach would be to take the ones digit and the
     * tens digit. Slightly simpler, though, is to take the ones digit; then,
     * to extract a second digit independent of the ones digit, consider which
     * of the 10 groups of 20 the random byte falls into: [0,19],
     * [20,39], ..., [180,199].
     *
     * If the random byte is in the range [200, 249], we can extract only one
     * unbiased digit from it: the ones digit.
     */
    while (pwdlen > 0) {
        gen_size = pwdlen / 2;
        if (pwdlen & 0x1) {
            gen_size++;
        }
        cprng_bytes(rng, rand_buf, gen_size);
        for (i = 0; i < gen_size; i++) {
            if (rand_buf[i] < 250) {
                *pwd = '0' + (char)(rand_buf[i] % 10);
                pwd++;
                pwdlen--;
            }
            if (pwdlen > 0 && rand_buf[i] < 200) {
                *pwd = '0' + (char)(rand_buf[i] / 20);
                pwd++;
                pwdlen--;
            }
        }
    }

    cprng_free_scrub(rng);
    scrub_memory(rand_buf, gen_size_max);
    free(rand_buf);
}

double bits_security_numeric(size_t pwdlen)
{
    /* log_2(10^n) == n * log_2(10) */
    return pwdlen * log2(10);
}
