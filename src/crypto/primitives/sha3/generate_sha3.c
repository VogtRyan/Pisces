
/*
 * Copyright (c) 2013-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#include <stdint.h>
#include <stdio.h>

/*
 * Generates and outputs the keccak_f function.
 */
static void generate_keccak_f(void);

/*
 * Computes the rotation constant in the rho step for the given x, y pair.
 */
static int compute_rotation_constant(int x, int y);

/*
 * Computes the SHA-3 round constant for the given round number.
 */
static uint64_t compute_round_constant(int round);

/*
 * Computes x^t mod (x^8 + x^6 + x^5 + x^4 + 1).
 */
static uint8_t x_to_the_t(int t);

/*
 * Computes the equivalent index into a two-dimensional array implemented as
 * one-dimensional.
 */
static int two_dim_array(int x, int y);

/*
 * Computes x mod m, returning a positive or zero value.
 */
static int mod(int x, int m);

int main(void)
{
    generate_keccak_f();
    return 0;
}

static void generate_keccak_f(void)
{
    int round, x, y, rot, i;
    uint64_t rc;

    /* Function header and variables */
    printf("static void keccak_f(struct sha3_ctx *ctx, "
           "const byte *new_data)\n{\n");
    printf("    uint64_t *a;\n");
    printf("    uint64_t b[25];\n");
    printf("    uint64_t c[5];\n");
    printf("    uint64_t d[5];\n");
    printf("    uint64_t i;\n");

    /*
     * Grab the new data. Let A[x,y] be the internal state of SHA-3, where
     * 0 <= x, y <= 4, and each element of A[x,y] is a 64-bit "lane" (integer).
     * The first step is to xor in the new data arriving to the hash state.
     *
     *   for 0 <= y <= 4:
     *     for 0 <= x <= 4:
     *       if no data remains, break
     *       A[x,y] = A[x,y] ^ ( next 64 bits of data )
     *
     * We implement A as a one-dimensional array in this code, but the
     * computation is equivalent.
     */
    printf("    a = ctx->state;\n");
    printf("    for (i = 0; i < ctx->rate / 8; i++) {\n");
    printf("        a[i] ^= get_little_end_64(new_data + 8 * i);\n");
    printf("    }\n");

    /* Unroll the rounds */
    for (round = 0; round < 24; round++) {
        /*
         * Theta:
         *   C[x]   = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]   for all x
         *   D[x]   = C[x-1] ^ ROT(C[x+1], 1)                      for all x
         *   A[x,y] = A[x,y] ^ D[x]                                for all x,y
         */
        for (x = 0; x < 5; x++) {
            printf("    c[%d] = a[%d] ^ a[%d] ^ a[%d] ^ a[%d] ^ a[%d];\n", x,
                   two_dim_array(x, 0), two_dim_array(x, 1),
                   two_dim_array(x, 2), two_dim_array(x, 3),
                   two_dim_array(x, 4));
        }
        for (x = 0; x < 5; x++) {
            printf("    d[%d] = c[%d] ^ ((c[%d] << 1) | (c[%d] >> 63));\n", x,
                   mod(x - 1, 5), mod(x + 1, 5), mod(x + 1, 5));
        }
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                printf("    a[%d] ^= d[%d];\n", two_dim_array(x, y), x);
            }
        }

        /*
         * Rho and Pi:
         *   B[y,2x+3y] = ROT(A[x,y], r[x,y])   for all x,y
         * where r[x,y] is the rotational constant, a function of x,y
         */
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                rot = compute_rotation_constant(x, y);
                if (rot != 0) {
                    printf("    b[%d] = ((a[%d] << %d) | (a[%d] >> %d));\n",
                           two_dim_array(y, 2 * x + 3 * y),
                           two_dim_array(x, y), rot, two_dim_array(x, y),
                           (64 - rot));
                }
                else {
                    printf("    b[%d] = a[%d];\n",
                           two_dim_array(y, 2 * x + 3 * y),
                           two_dim_array(x, y));
                }
            }
        }

        /*
         * Chi and Iota:
         *   A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])   for all x, y
         *   A[0,0] = A[0,0] ^ rc
         * where rc is the round constant, a function of the round number
         */
        for (x = 0; x < 5; x++) {
            for (y = 0; y < 5; y++) {
                printf("    a[%d] = b[%d] ^ ((~b[%d]) & b[%d])",
                       two_dim_array(x, y), two_dim_array(x, y),
                       two_dim_array(x + 1, y), two_dim_array(x + 2, y));
                if (x == 0 && y == 0) {
                    rc = compute_round_constant(round);
                    printf(" ^ 0x");
                    for (i = 7; i >= 0; i--) {
                        printf("%02X", (uint8_t)((rc >> (8 * i)) & 0xFF));
                    }
                    printf("ULL");
                }
                printf(";\n");
            }
        }
    }

    printf("}\n");
}

static int compute_rotation_constant(int x, int y)
{
    int current_x, current_y, tmp, t;

    if (x == 0 && y == 0) {
        return 0;
    }

    current_x = 1;
    current_y = 0;
    for (t = 0; t < 24; t++) {
        if (current_x == x && current_y == y) {
            return ((t + 1) * (t + 2) / 2) % 64;
        }
        tmp = current_y;
        current_y = (2 * current_x + 3 * current_y) % 5;
        current_x = tmp;
    }
    return -1;
}

static uint64_t compute_round_constant(int round)
{
    uint64_t rnd_const;
    uint8_t rct;
    int j, bit, i;

    rnd_const = 0;
    for (j = 0; j <= 6; j++) {
        rct = x_to_the_t(j + 7 * round);
        if (rct & 0x01) {
            bit = 1;
            for (i = 0; i < j; i++) {
                bit = bit << 1;
            }
            bit = bit - 1;
            rnd_const |= (((uint64_t)1) << bit);
        }
    }
    return rnd_const;
}

static uint8_t x_to_the_t(int t)
{
    uint8_t res = 0x01;
    while (t > 0) {
        if (res & 0x80) {
            res = (uint8_t)((res << 1) ^ 0x71);
        }
        else {
            res <<= 1;
        }
        t--;
    }
    return res;
}

static int two_dim_array(int x, int y)
{
    int a, b;
    a = mod(x, 5);
    b = mod(y, 5);
    return 5 * b + a;
}

static int mod(int x, int m)
{
    while (x < 0) {
        x += m;
    }
    return x % m;
}
