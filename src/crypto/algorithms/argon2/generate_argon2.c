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

static void output_compression_fn_g_preamble(void);
static void output_compression_fn_g_tail(void);
static void output_compression_fn_g_core(void);

static void output_p(int *reg_indices);
static void output_gb(int a, int b, int c, int d);
static void output_add_mult_op(int x, int y);
static void output_circ_shift_op(int x, int y, int amnt);

int main(void)
{
    output_compression_fn_g_preamble();
    output_compression_fn_g_core();
    output_compression_fn_g_tail();
    return 0;
}

static void output_compression_fn_g_preamble(void)
{
    printf("static void compression_fn_g(");
    printf("byte *output_block, const byte *block_x,\n");
    printf("                             ");
    printf("const byte *block_y, bool xor_output)\n");
    printf("{\n");

    printf("    uint64_t f[BLOCK_BYTES / 8];\n");
    printf("    byte r[BLOCK_BYTES];\n");
    printf("    byte z[BLOCK_BYTES];\n");
    printf("    size_t i;\n\n");

    printf("    for (i = 0; i < BLOCK_BYTES; i++) {\n");
    printf("        r[i] = block_x[i] ^ block_y[i];\n");
    printf("    }\n\n");

    printf("    for (i = 0; i < BLOCK_BYTES / 16; i++) {\n");
    printf("        f[2 * i] = get_little_end_64(r + i * 16);\n");
    printf("        f[2 * i + 1] = get_little_end_64(r + i * 16 + 8);\n");
    printf("    }\n\n");
}

static void output_compression_fn_g_tail(void)
{
    printf("\n");
    printf("    for (i = 0; i < BLOCK_BYTES / 16; i++) {\n");
    printf("        put_little_end_64(z + i * 16, f[2 * i]);\n");
    printf("        put_little_end_64(z + i * 16 + 8, f[2 * i + 1]);\n");
    printf("    }\n\n");
    printf("    if (xor_output) {\n");
    printf("        for (i = 0; i < BLOCK_BYTES; i++) {\n");
    printf("            output_block[i] ^= z[i] ^ r[i];\n");
    printf("        }\n");
    printf("    }\n");
    printf("    else {\n");
    printf("        for (i = 0; i < BLOCK_BYTES; i++) {\n");
    printf("            output_block[i] = z[i] ^ r[i];\n");
    printf("        }\n");
    printf("    }\n");
    printf("}\n");
}

static void output_compression_fn_g_core(void)
{
    int indices[8];
    int base_index, i;

    /*
     * Per RFC 9106, section 3.5 - first set of P operations:
     *
     * ( Q_0,  Q_1,  Q_2, ... ,  Q_7) <- P( R_0,  R_1,  R_2, ... ,  R_7)
     * ( Q_8,  Q_9, Q_10, ... , Q_15) <- P( R_8,  R_9, R_10, ... , R_15)
     *                               ...
     * (Q_56, Q_57, Q_58, ... , Q_63) <- P(R_56, R_57, R_58, ... , R_63)
     */
    for (base_index = 0; base_index < 64; base_index += 8) {
        for (i = 0; i < 8; i++) {
            indices[i] = base_index + i;
        }
        output_p(indices);
    }

    /*
     * Per RFC 9106, section 3.5 - second set of P operations:
     *
     * ( Z_0,  Z_8, Z_16, ... , Z_56) <- P(Q_0,  Q_8, Q_16, ... , Q_56)
     * ( Z_1,  Z_9, Z_17, ... , Z_57) <- P(Q_1,  Q_9, Q_17, ... , Q_57)
     *                               ...
     * ( Z_7, Z_15, Z 23, ... , Z_63) <- P(Q_7, Q_15, Q_23, ... , Q_63)
     */
    for (base_index = 0; base_index < 8; base_index++) {
        for (i = 0; i < 8; i++) {
            indices[i] = base_index + 8 * i;
        }
        output_p(indices);
    }
}

static void output_p(int *reg_indices)
{
    int v_to_flat[16];
    int i;

    /*
     * The permutation P takes eight 128-bit registers as input:
     *
     *     (S_0, S_1, ..., S_7).
     *
     * Each register can be viewed (conceptually) as two consecutive uint64_t
     * values in an array "v":
     *
     *     uint64_t v[16];
     *
     * There are 64 registers in total, representing the 1024-byte block, and
     * they can be stored (actually) in a flat array:
     *
     *     uint64_t f[128];
     *
     * We want to avoid having to build a v[16] array as input for every call
     * to P. Instead, this function takes an array, indices[i], 0 <= i < 8, as
     * input. Each element is a register index, 0 <= indices[i] < 64. We build
     * a mapping, v_to_flat[i], 0 <= i < 16, translating an index in the
     * virtual "v" array into an index in the "f" array.
     */
    for (i = 0; i < 8; i++) {
        v_to_flat[2 * i] = 2 * reg_indices[i];
        v_to_flat[2 * i + 1] = 2 * reg_indices[i] + 1;
    }

    output_gb(v_to_flat[0], v_to_flat[4], v_to_flat[8], v_to_flat[12]);
    output_gb(v_to_flat[1], v_to_flat[5], v_to_flat[9], v_to_flat[13]);
    output_gb(v_to_flat[2], v_to_flat[6], v_to_flat[10], v_to_flat[14]);
    output_gb(v_to_flat[3], v_to_flat[7], v_to_flat[11], v_to_flat[15]);

    output_gb(v_to_flat[0], v_to_flat[5], v_to_flat[10], v_to_flat[15]);
    output_gb(v_to_flat[1], v_to_flat[6], v_to_flat[11], v_to_flat[12]);
    output_gb(v_to_flat[2], v_to_flat[7], v_to_flat[8], v_to_flat[13]);
    output_gb(v_to_flat[3], v_to_flat[4], v_to_flat[9], v_to_flat[14]);
}

/*
 * This implementation of the GB() function takes indices into the flat array,
 * f[128], instead of into a virtual array, v[16].
 */
static void output_gb(int a, int b, int c, int d)
{
    output_add_mult_op(a, b);
    output_circ_shift_op(d, a, 32);

    output_add_mult_op(c, d);
    output_circ_shift_op(b, c, 24);

    output_add_mult_op(a, b);
    output_circ_shift_op(d, a, 16);

    output_add_mult_op(c, d);
    output_circ_shift_op(b, c, 63);
}

static void output_add_mult_op(int x, int y)
{
    printf("    f[%d] += f[%d] + 2 * (f[%d] & UINT32_MAX) * (f[%d] & "
           "UINT32_MAX);\n",
           x, y, x, y);
}

static void output_circ_shift_op(int x, int y, int amnt)
{
    printf("    f[%d] = ((f[%d] ^ f[%d]) >> %d) | ((f[%d] ^ f[%d]) << %d);\n",
           x, x, y, amnt, x, y, 64 - amnt);
}
