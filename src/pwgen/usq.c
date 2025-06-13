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

#include "usq.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/cprng.h"

#include <math.h>
#include <stdbool.h>
#include <stddef.h>

static void fill_usq_simple(char *result, size_t num, struct cprng *rng);
static bool has_upper_lower_num_special(const char *pwd, size_t pwdlen);

void generate_pwd_usq_simple(char *pwd, size_t pwdlen)
{
    struct cprng *rng;

    rng = cprng_alloc_default();
    fill_usq_simple(pwd, pwdlen, rng);

    cprng_free_scrub(rng);
}

double bits_security_usq_simple(size_t pwdlen)
{
    /* log_2(72^n) == n * log_2(72) */
    return pwdlen * log2(72);
}

void generate_pwd_usq_simple_enforced(char *pwd, size_t pwdlen)
{
    struct cprng *rng;

    ASSERT(pwdlen >= 4, "An enforced password must have length of at least 4");

    rng = cprng_alloc_default();
    do {
        fill_usq_simple(pwd, pwdlen, rng);
    } while (has_upper_lower_num_special(pwd, pwdlen) == false);

    cprng_free_scrub(rng);
}

/*
 * Computing the number of bits of security for enforced passwords:
 *
 * Denote n = password length, n >= 4.
 *
 * Define sets:
 *   P = capital letters (26)
 *   Q = lowercase letters (26)
 *   R = numbers (10)
 *   S = symbols (10)
 *
 * Number of USQ simple passwords, without any enforcement that they contain
 * one character from each set: 72^n
 *
 * Invalid passwords, because they lack characters from one set:
 *   Passwords without P = (72-26)^n = 46^n
 *   Passwords without Q = (72-26)^n = 46^n
 *   Passwords without R = (72-10)^n = 62^n
 *   Passwords without S = (72-10)^n = 62^n
 *   Sum = 2*62^n + 2*46^n
 *
 * Invalid passwords, because they lack characters from two sets:
 *   Passwords without P/Q = (72-26-26)^n = 20^n
 *   Passwords without P/R = (72-26-10)^n = 36^n
 *   Passwords without P/S = (72-26-10)^n = 36^n
 *   Passwords without Q/R = (72-26-10)^n = 36^n
 *   Passwords without Q/S = (72-26-10)^n = 36^n
 *   Passwords without R/S = (72-10-10)^n = 52^n
 *   Sum = 52^n + 4*36^n + 20^n
 *
 * Invalid passwords, because they lack characters from three sets:
 *   Passwords without P/Q/R = (72-26-26-10)^n = 10^n
 *   Passwords without P/Q/S = (72-26-26-10)^n = 10^n
 *   Passwords without P/R/S = (72-26-10-10)^n = 26^n
 *   Passwords without Q/R/S = (72-26-10-10)^n = 26^n
 *   Sum = 2*26^n + 2*10^n
 *
 * Number of valid passwords, per the inclusion-exclusion principle:
 * v(n) = 72^n - (2*62^n + 2*46^n) + (52^n + 4*36^n + 20^n) - (2*26^n + 2*10^n)
 *      = 72^n - 2*62^n + 52^n - 2*46^n + 4*36^n - 2*26^n + 20^n - 2*10^n
 *
 * Note: v(n) > 0 for all integers n >= 4, so log_2(v(n)) is well-defined for
 * n >= 4.
 *
 * Computing log_2(v(n)) directly would overflow for large n, so move the
 * computation into log space.
 *
 * Denote each term of v(n) as a_i = (c_i) * (b_i)^n
 *   a_0 = ( 1) * (72)^n
 *   a_1 = (-2) * (62)^n
 *   [...]
 *   a_7 = (-2) * (10)^n
 *
 * Rewrite in log space: a_i = (c_i) * 2^(n * log_2(b_i))
 *   a_0 = ( 1) * 2^(n * log_2(72))
 *   a_1 = (-2) * 2^(n * log_2(62))
 *   [...]
 *   a_7 = (-2) * 2^(n * log_2(10))
 *
 * Denote each exponent as x_i:
 *   x_0 = n * log_2(72)
 *   x_1 = n * log_2(62)
 *   [...]
 *   x_7 = n * log_2(10)
 *
 * So, v(n) = sum_{i}[c_i * 2^(x_i)]
 *
 * Denote x_max = max(x_i) = n * log_2(72) = x_0
 *
 * Factor 2^(x_max) out of the sum:
 * v(n) = 2^{x_max} * sum_{i}[c_i * 2^(x_i - x_max)]
 *
 * Compute log_2(v(n)) from that expression of v(n):
 * log_2(v(n)) = log_2[2^(x_max) * sum_{i}[c_i * 2^(x_i - x_max)]]
 *             = log_2[2^(x_max)] + log_2[sum_{i}[c_i * 2^(x_i - x_max)]]]
 *             = x_max + log_2[sum_{i}[c_i * 2^(x_i - x_max)]]
 *             = x_0 + log_2[sum_{i}[c_i * 2^(x_i - x_0)]]
 */
double bits_security_usq_simple_enforced(size_t pwdlen)
{
    const double bases[] = {72, 62, 52, 46, 36, 26, 20, 10};
    const double coefficients[] = {1, -2, 1, -2, 4, -2, 1, -2};
    const size_t num_bases = sizeof(bases) / sizeof(double);

    double x[num_bases];
    double sum;
    size_t i;

    ASSERT(pwdlen >= 4, "Bits of security undefined for password length < 4");

    for (i = 0; i < num_bases; i++) {
        x[i] = pwdlen * log2(bases[i]);
    }

    sum = 0.0;
    for (i = 0; i < num_bases; i++) {
        sum += coefficients[i] * pow(2.0, x[i] - x[0]);
    }

    return x[0] + log2(sum);
}

static void fill_usq_simple(char *pwd, size_t pwdlen, struct cprng *rng)
{
    byte *rand_buf;
    size_t gen_size, gen_size_max, i;

    gen_size_max = pwdlen;
    rand_buf = (byte *)malloc(gen_size_max);
    GUARD_ALLOC(rand_buf);

    /*
     * There are 72 legal characters (26 + 26 + 10 + 10), so we can use
     * 72*3 = 216/256 possible values of a byte to generate an unbiased
     * character.
     */
    while (pwdlen > 0) {
        gen_size = pwdlen;
        cprng_bytes(rng, rand_buf, gen_size);
        for (i = 0; i < gen_size; i++) {
            if (rand_buf[i] >= 216) {
                continue;
            }
            if (rand_buf[i] < 78) {
                /* Lower case letters */
                *pwd = (char)((int)rand_buf[i] % 26 + 97);
            }
            else if (rand_buf[i] < 156) {
                /* Upper case letters */
                *pwd = (char)((int)rand_buf[i] % 26 + 65);
            }
            else if (rand_buf[i] < 186) {
                /* Numbers */
                *pwd = (char)((int)rand_buf[i] % 10 + 48);
            }
            else if (rand_buf[i] < 189) {
                *pwd = '!';
            }
            else if (rand_buf[i] < 192) {
                *pwd = '@';
            }
            else if (rand_buf[i] < 195) {
                *pwd = '#';
            }
            else if (rand_buf[i] < 198) {
                *pwd = '$';
            }
            else if (rand_buf[i] < 201) {
                *pwd = '%';
            }
            else if (rand_buf[i] < 204) {
                *pwd = '^';
            }
            else if (rand_buf[i] < 207) {
                *pwd = '&';
            }
            else if (rand_buf[i] < 210) {
                *pwd = '*';
            }
            else if (rand_buf[i] < 213) {
                *pwd = '(';
            }
            else {
                *pwd = ')';
            }
            pwdlen--;
            pwd++;
        }
    }

    scrub_memory(rand_buf, gen_size_max);
    free(rand_buf);
}

static bool has_upper_lower_num_special(const char *pwd, size_t pwdlen)
{
    bool has_upper, has_lower, has_number, has_special;
    size_t i;

    has_upper = has_lower = has_number = has_special = false;
    for (i = 0; i < pwdlen; i++) {
        if (*pwd >= (char)65 && *pwd <= (char)90) {
            has_upper = true;
        }
        else if (*pwd >= (char)97 && *pwd <= (char)122) {
            has_lower = true;
        }
        else if (*pwd >= (char)48 && *pwd <= (char)57) {
            has_number = true;
        }
        else {
            has_special = true;
        }
        pwd++;
    }

    return (has_upper && has_lower && has_number && has_special);
}
