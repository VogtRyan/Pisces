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

#include "common/errorflow.h"

#include <limits.h>
#include <math.h>
#include <stddef.h>
#include <stdio.h>

#define TERM_BOUND (1e-15L)

struct pi_digit_indices {
    unsigned long index_lb;
    unsigned long index_ub;
};

static struct pi_digit_indices indices[] = {
    {
        .index_lb = 0,
        .index_ub = 360,
    },
    {
        .index_lb = 0,
        .index_ub = 640,
    },
    {
        .index_lb = 360,
        .index_ub = 720,
    },
    {
        .index_lb = 640,
        .index_ub = 704,
    },
};

static char pi_hex_digit(unsigned long index);
static long double compute_sum(unsigned long j, unsigned long n);
static unsigned long compute_denom_term(unsigned long k, unsigned long j);

static unsigned long powmod(unsigned long base, unsigned long exponent,
                            unsigned long modulus);

int main(void)
{
    char *digits;
    unsigned long smallest_lb, largest_ub, on_char;
    size_t i;

    smallest_lb = ULONG_MAX;
    largest_ub = 0;
    for (i = 0; i < sizeof(indices) / sizeof(struct pi_digit_indices); i++) {
        ASSERT(indices[i].index_lb <= indices[i].index_ub, "Invalid indices");
        if (indices[i].index_lb < smallest_lb) {
            smallest_lb = indices[i].index_lb;
        }
        if (indices[i].index_ub > largest_ub) {
            largest_ub = indices[i].index_ub;
        }
    }

    digits = calloc((size_t)(largest_ub - smallest_lb), sizeof(char));
    GUARD_ALLOC(digits);

    for (on_char = smallest_lb; on_char < largest_ub; on_char++) {
        digits[on_char - smallest_lb] = pi_hex_digit(on_char);
    }

    for (i = 0; i < sizeof(indices) / sizeof(struct pi_digit_indices); i++) {
        if (i != 0) {
            printf("\n");
        }
        printf("#define PI_DIGITS_%lu_%lu \"", indices[i].index_lb,
               indices[i].index_ub);
        for (on_char = indices[i].index_lb; on_char < indices[i].index_ub;
             on_char++) {
            printf("%c", digits[on_char - smallest_lb]);
        }
        printf("\"\n");
    }

    free(digits);
    return 0;
}

/*
 * Return the hexadecimal digit of pi at position n, where n is zero-based
 * and starts after the decimal point.
 *
 * In hex:
 *     pi = 3.243F6A8885A...
 * pi_hex_digit(0) = 2
 * pi_hex_digit(1) = 4
 * pi_hex_digit(2) = 3
 * pi_hex_digit(3) = F
 *
 * This computation uses the Bailey-Borwein-Plouffe (BBP) formula, and can be
 * verified against Blowfish's P-array followed by its S-boxes.
 */
static char pi_hex_digit(unsigned long index)
{
    long double frac_part;
    unsigned int digit;

    frac_part = 4 * compute_sum(1, index) - 2 * compute_sum(4, index) -
                compute_sum(5, index) - compute_sum(6, index);
    frac_part -= floorl(frac_part);

    digit = (unsigned int)(frac_part * 16.0L);
    if (digit < 10) {
        return '0' + digit;
    }
    else {
        return 'A' + (digit - 10);
    }
}

/*
 * Computes
 *     S_j(n) = sum_{k=0}^{infinity} 16^(n-k) / (8k + j)
 * and returns the fractional part.
 *
 * This function does so by breaking the sum into two parts:
 *     sum_{k=0  }^{n}        [ 16^(n-k) mod (8k + j) ] / (8k + j)
 *     sum_{k=n+1}^{infinity} [ 16^(n-k)              ] / (8k + j)
 */
static long double compute_sum(unsigned long j, unsigned long n)
{
    long double sum, term;
    unsigned long denom_term, k;

    ASSERT(n < ULONG_MAX, "Computation of n+1 will overflow");

    sum = 0.0;
    for (k = 0; k < n + 1; k++) {
        denom_term = compute_denom_term(k, j);
        sum += (long double)powmod(16UL, n - k, denom_term) / denom_term;
        sum -= floorl(sum);
    }

    k = n + 1;
    while (1) {
        denom_term = compute_denom_term(k, j);
        term = powl(16.0L, (long double)n - k) / denom_term;
        if (term < TERM_BOUND) {
            break;
        }
        sum += term;

        k++;
        ASSERT(k != 0, "Addition overflow in infinite term computation");
    }

    return sum - floorl(sum);
}

/*
 * Computes the denominator term in the series expansion:
 *    8 * k + j
 */
static unsigned long compute_denom_term(unsigned long k, unsigned long j)
{
    unsigned long res;

    ASSERT(k <= ULONG_MAX / 8, "Multiplication overflow");
    k *= 8;

    res = k + j;
    ASSERT(res >= k, "Addition overflow");

    return res;
}

static unsigned long powmod(unsigned long base, unsigned long exponent,
                            unsigned long modulus)
{
    unsigned long long b, m, res;

    ASSERT(modulus != 0, "Modulus must be positive");
    base %= modulus;

    /*
     * Both b and res will be bounded by m. So, as long as we can multiply m by
     * itself without overflow, we are guaranteed that this function will never
     * overflow.
     */
    b = (unsigned long long)base;
    m = (unsigned long long)modulus;
    ASSERT(m <= ULLONG_MAX / m, "Modulus too large (%llu)", m);

    res = 1;
    while (exponent > 0) {
        if (exponent & 1U) {
            res = (b * res) % m;
        }
        b = (b * b) % m;
        exponent >>= 1U;
    }

    /* Bounded by modulus, so cast is safe */
    return (unsigned long)res;
}
