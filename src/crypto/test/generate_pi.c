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
    size_t index_lb;
    size_t index_ub;
};

static struct pi_digit_indices defines[] = {
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

static size_t num_digits_to_generate(void);

static char pi_hex_digit(size_t index);
static long double compute_sum(unsigned long j, unsigned long n);
static unsigned long compute_denom_term(unsigned long k, unsigned long j);
static unsigned long powmod(unsigned long base, unsigned long exponent,
                            unsigned long modulus);

static void output_defines(const char *digits);
static void output_define(const char *digits, size_t index_lb,
                          size_t index_ub);

int main(void)
{
    char *digits;
    size_t num_digits, on_digit;

    num_digits = num_digits_to_generate();
    digits = calloc(num_digits, sizeof(char));
    GUARD_ALLOC(digits);

    for (on_digit = 0; on_digit < num_digits; on_digit++) {
        digits[on_digit] = pi_hex_digit(on_digit);
    }
    output_defines(digits);

    free(digits);
    return 0;
}

static size_t num_digits_to_generate(void)
{
    size_t num_defines, on_define;
    size_t largest_ub, ub;

    num_defines = sizeof(defines) / sizeof(struct pi_digit_indices);
    largest_ub = 0;

    for (on_define = 0; on_define < num_defines; on_define++) {
        ub = defines[on_define].index_ub;
        if (ub > largest_ub) {
            largest_ub = ub;
        }
    }

    /* Assume we should generate all digits with indices in [0, largest_ub) */
    return largest_ub;
}

/*
 * Return the hexadecimal digit of pi at position n, where n is zero-based
 * and starts after the decimal point.
 *
 * In hexadecimal:
 *     pi = 3.243F6A8885A...
 * pi_hex_digit(0) == '2'
 * pi_hex_digit(1) == '4'
 * pi_hex_digit(2) == '3'
 * pi_hex_digit(3) == 'F'
 *
 * This computation uses the Bailey-Borwein-Plouffe (BBP) formula, and the
 * first 8336 digits have been verified against Blowfish's P-array followed by
 * its four S-boxes.
 */
static char pi_hex_digit(size_t index)
{
    long double frac_part;
    unsigned long n;
    int digit;

    n = (unsigned long)index;
    ASSERT(index == n, "Index too large to cast (index=%zu, n=%lu)", index, n);

    frac_part = 4 * compute_sum(1, n) - 2 * compute_sum(4, n) -
                compute_sum(5, n) - compute_sum(6, n);
    frac_part -= floorl(frac_part);

    digit = (int)(frac_part * 16.0L);
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

    ASSERT(n < ULONG_MAX, "Addition overflow on n+1 (j=%lu, n=%lu)", j, n);

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
        ASSERT(k != 0, "Addition overflow on k++ (j=%lu, n=%lu)", j, n);
    }

    return sum - floorl(sum);
}

/* Computes the denominator term in the series expansion: 8k + j */
static unsigned long compute_denom_term(unsigned long k, unsigned long j)
{
    unsigned long eight_k, res;

    ASSERT(k <= ULONG_MAX / 8, "Multiplication overflow (k=%lu, j=%lu)", k, j);
    eight_k = 8 * k;

    res = eight_k + j;
    ASSERT(res >= eight_k, "Addition overflow (k=%lu, j=%lu)", k, j);

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

static void output_defines(const char *digits)
{
    size_t num_defines, on_define;

    num_defines = sizeof(defines) / sizeof(struct pi_digit_indices);

    for (on_define = 0; on_define < num_defines; on_define++) {
        if (on_define != 0) {
            printf("\n");
        }
        output_define(digits, defines[on_define].index_lb,
                      defines[on_define].index_ub);
    }
}

static void output_define(const char *digits, size_t index_lb, size_t index_ub)
{
    size_t on_digit;

    ASSERT(index_lb < index_ub, "Invalid indices (index_lb=%zu, index_ub=%zu)",
           index_lb, index_ub);

    printf("#define PI_FRACTIONAL_HEX_DIGITS_%zu_%zu \"", index_lb, index_ub);
    for (on_digit = index_lb; on_digit < index_ub; on_digit++) {
        printf("%c", digits[on_digit]);
    }
    printf("\"\n");
}
