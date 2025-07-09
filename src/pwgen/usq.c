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

static void fill_usq_simple(char *pwd, size_t pwdlen, struct cprng *rng);
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
 * To compute the number of bits of security for enforced passwords of length
 * n >= 4, first compute
 *   v(n) = the number of valid, enforced passwords of length n
 * The number of bits of security will be equal to log_2(v(n)).
 *
 * Let U ("universal") be the set of all USQ simple passwords of length n,
 * whether they are valid, enforced passwords or not. |U| = 72^n.
 *
 * Let D ("discarded") be the set of all USQ simple passwords of length n that
 * are not valid, enforced passwords.
 *
 * v(n) = |U| - |D|
 *      = 72^n - |D|
 *
 * Define subsets of D based on why passwords were discarded as invalid:
 *   P = passwords without any of the 26 capital letters
 *   Q = passwords without any of the 26 lowercase letters
 *   R = passwords without any of the 10 numbers
 *   S = passwords without any of the 10 symbols
 *
 * Use <union> to represent the set-union operation, and use & to represent the
 * set-intersection operation.
 *
 * All discarded passwords belong to at least one of P, Q, R, or S, meaning
 *   D = P <union> Q <union> R <union> S
 *
 * Compute |D| using the inclusion-exclusion principle:
 *   |D| = Sum_{subset} - Sum_{two-way} + Sum_{three-way} - |P & Q & R & S|
 * where:
 *   Sum_{subset}    = sum of sizes of the four subsets
 *   Sum_{two-way}   = sum of sizes of all the two-way intersections
 *   Sum_{three-way} = sum of sizes of all the three-way intersections
 *   |P & Q & R & S| = size of the four-way intersection
 *
 * Single subsets:
 *   |P| = (72-26)^n = 46^n
 *   |Q| = (72-26)^n = 46^n
 *   |R| = (72-10)^n = 62^n
 *   |S| = (72-10)^n = 62^n
 *   Sum_{subset} = 2*62^n + 2*46^n
 *
 * Two-way intersections:
 *   |P & Q| = (72-26-26)^n = 20^n
 *   |P & R| = (72-26-10)^n = 36^n
 *   |P & S| = (72-26-10)^n = 36^n
 *   |Q & R| = (72-26-10)^n = 36^n
 *   |Q & S| = (72-26-10)^n = 36^n
 *   |R & S| = (72-10-10)^n = 52^n
 *   Sum_{two-way} = 52^n + 4*36^n + 20^n
 *
 * Three-way intersections:
 *   |P & Q & R| = (72-26-26-10)^n = 10^n
 *   |P & Q & S| = (72-26-26-10)^n = 10^n
 *   |P & R & S| = (72-26-10-10)^n = 26^n
 *   |Q & R & S| = (72-26-10-10)^n = 26^n
 *   Sum_{three-way} = 2*26^n + 2*10^n
 *
 * Four-way intersection:
 *   |P & Q & R & S| = 0
 * because no simple password lacks all four character types.
 *
 * |D| = Sum_{subset} - Sum_{two-way} + Sum_{three-way} - |P & Q & R & S|
 *     = (2*62^n + 2*46^n) - (52^n + 4*36^n + 20^n) + (2*26^n + 2*10^n) - (0)
 *     = 2*62^n - 52^n + 2*46^n - 4*36^n + 2*26^n - 20^n + 2*10^n
 *
 * v(n) = |U| - |D|
 *      = 72^n - (2*62^n - 52^n + 2*46^n - 4*36^n + 2*26^n - 20^n + 2*10^n)
 *      = 72^n - 2*62^n + 52^n - 2*46^n + 4*36^n - 2*26^n + 20^n - 2*10^n
 *
 * Note: v(n) > 0 for all integers n >= 4, so log_2(v(n)) is well-defined for
 * n >= 4.
 *
 * Computing log_2(v(n)) directly from v(n) would overflow for large n.
 * Specifically, pow(72.0, n) overflows an IEEE 754 binary64 double when
 * n >= 166. So, move the computation into log space.
 *
 * Denote each term of v(n) as a_i = (c_i) * (b_i)^n
 *   a_0 = ( 1) * (72)^n
 *   a_1 = (-2) * (62)^n
 *   a_2 = ( 1) * (52)^n
 *   a_3 = (-2) * (46)^n
 *   a_4 = ( 4) * (36)^n
 *   a_5 = (-2) * (26)^n
 *   a_6 = ( 1) * (20)^n
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
 * Denote x_max = max_{i}(x_i)
 *              = n * log_2(72)
 *              = x_0
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
