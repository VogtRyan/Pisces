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

#include <stdio.h>

/* RFC 7693, section 2.7 */
static const int SIGMA[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}};

static void output_compress_fn_f_preamble(void);
static void output_compress_fn_f_tail(void);

static void output_compress_fn_f_core(void);
static void output_mix_fn_g(int a, int b, int c, int d, int i, int xj, int yj);
static void output_xor_circ_right_shift(int index_a, int index_b, int amnt);
static int sigma(int i, int j);

int main(void)
{
    output_compress_fn_f_preamble();
    output_compress_fn_f_core();
    output_compress_fn_f_tail();
    return 0;
}

static void output_compress_fn_f_preamble(void)
{
    printf("static void compress_fn_f(struct blake2b_ctx *ctx, "
           "const byte *input_block,\n"
           "                          bool final_block)\n");
    printf("{\n");

    printf("    uint64_t v[16];\n");
    printf("    uint64_t m[16];\n");
    printf("    int i;\n\n");

    printf("    memcpy(v, ctx->state_h, 8 * sizeof(uint64_t));\n");
    printf("    memcpy(v + 8, IV, 8 * sizeof(uint64_t));\n\n");

    printf("    v[12] ^= ctx->bytes_processed_t_low;\n");
    printf("    v[13] ^= ctx->bytes_processed_t_high;\n\n");

    printf("    if (final_block) {\n");
    printf("        v[14] = ~v[14];\n");
    printf("    }\n\n");

    printf("    for (i = 0; i < 16; i++) {\n");
    printf("        m[i] = get_little_end_64(input_block + 8 * i);\n");
    printf("    }\n\n");
}

static void output_compress_fn_f_tail(void)
{

    printf("\n");
    printf("    for (i = 0; i < 8; i++) {\n");
    printf("        ctx->state_h[i] ^= v[i] ^ v[i + 8];\n");
    printf("    }\n");
    printf("}\n");
}

static void output_compress_fn_f_core(void)
{
    int i;

    for (i = 0; i < 12; i++) {
        output_mix_fn_g(0, 4, 8, 12, i, 0, 1);
        output_mix_fn_g(1, 5, 9, 13, i, 2, 3);
        output_mix_fn_g(2, 6, 10, 14, i, 4, 5);
        output_mix_fn_g(3, 7, 11, 15, i, 6, 7);
        output_mix_fn_g(0, 5, 10, 15, i, 8, 9);
        output_mix_fn_g(1, 6, 11, 12, i, 10, 11);
        output_mix_fn_g(2, 7, 8, 13, i, 12, 13);
        output_mix_fn_g(3, 4, 9, 14, i, 14, 15);
    }
}

static void output_mix_fn_g(int a, int b, int c, int d, int i, int xj, int yj)
{

    printf("    v[%d] += v[%d] + m[%d];\n", a, b, sigma(i, xj));
    output_xor_circ_right_shift(d, a, 32);
    printf("    v[%d] += v[%d];\n", c, d);
    output_xor_circ_right_shift(b, c, 24);
    printf("    v[%d] += v[%d] + m[%d];\n", a, b, sigma(i, yj));
    output_xor_circ_right_shift(d, a, 16);
    printf("    v[%d] += v[%d];\n", c, d);
    output_xor_circ_right_shift(b, c, 63);
}

static void output_xor_circ_right_shift(int index_a, int index_b, int amnt)
{
    /* Could be output as two lines (xor then shift) or as one */
    printf("    v[%d] = ((v[%d] ^ v[%d]) >> %d) | ((v[%d] ^ v[%d]) << %d);\n",
           index_a, index_a, index_b, amnt, index_a, index_b, 64 - amnt);
}

static int sigma(int i, int j)
{
    return SIGMA[i % 10][j];
}
