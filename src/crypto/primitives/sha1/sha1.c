/*
 * Copyright (c) 2011-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "sha1.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/machine/bitops.h"
#include "crypto/machine/endian.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define SHA1_MAX_MESSAGE_BYTES ((uint64_t)(0x1FFFFFFFFFFFFFFFLLU))

struct sha1_ctx {
    uint32_t h[5];
    uint64_t bytes_processed;
    byte block[SHA1_BLOCK_BYTES];
    uint8_t bytes_in_block;
    bool bytes_exceeded;
};

/*
 * Process a single block of data into the SHA-1 context. Assumes the number
 * of bytes processed, including the given block, does not exceed the maximum
 * message length of SHA-1.
 */
static void sha1_process_block(struct sha1_ctx *ctx, const byte *block);

/*
 * Adds the given number of bytes to the context's count of bytes processed.
 * Returns 0 on success, or -1 if the maximum message size is exceeded.
 */
static int add_num_bytes(struct sha1_ctx *ctx, size_t num_bytes);
static bool addition_would_overflow_u64(uint64_t a, size_t b);

struct sha1_ctx *sha1_alloc(void)
{
    struct sha1_ctx *ret =
        (struct sha1_ctx *)calloc(1, sizeof(struct sha1_ctx));
    GUARD_ALLOC(ret);
    return ret;
}

void sha1_start(struct sha1_ctx *ctx)
{
    ctx->h[0] = (uint32_t)0x67452301;
    ctx->h[1] = (uint32_t)0xEFCDAB89;
    ctx->h[2] = (uint32_t)0x98BADCFE;
    ctx->h[3] = (uint32_t)0x10325476;
    ctx->h[4] = (uint32_t)0xC3D2E1F0;
    ctx->bytes_processed = 0;
    ctx->bytes_in_block = 0;
    ctx->bytes_exceeded = false;
}

int sha1_add(struct sha1_ctx *ctx, const byte *bytes, size_t num_bytes)
{
    size_t to_fill_block, add_to_ctx;

    /* Update the number of bytes processed by the context */
    if (add_num_bytes(ctx, num_bytes)) {
        return -1;
    }

    /* Process the data in blocks */
    while (num_bytes > 0) {
        if (ctx->bytes_in_block == 0 && num_bytes >= SHA1_BLOCK_BYTES) {
            sha1_process_block(ctx, bytes);
            bytes += SHA1_BLOCK_BYTES;
            num_bytes -= SHA1_BLOCK_BYTES;
        }
        else {
            to_fill_block = SHA1_BLOCK_BYTES - ctx->bytes_in_block;
            add_to_ctx = MIN(to_fill_block, num_bytes);
            memcpy(ctx->block + ctx->bytes_in_block, bytes, add_to_ctx);
            ctx->bytes_in_block += add_to_ctx;
            bytes += add_to_ctx;
            num_bytes -= add_to_ctx;
            if (ctx->bytes_in_block == SHA1_BLOCK_BYTES) {
                ctx->bytes_in_block = 0;
                sha1_process_block(ctx, ctx->block);
            }
        }
    }

    return 0;
}

int sha1_end(struct sha1_ctx *ctx, byte *digest)
{
    byte to_append[SHA1_BLOCK_BYTES + 8];
    uint64_t total_bits;
    size_t num_to_append;
    int i;

    if (ctx->bytes_exceeded) {
        return -1;
    }

    total_bits = ctx->bytes_processed * 8;

    /*
     * Append 0x80 0x00 0x00 0x00 ... 0x00 so that the resulting amount of data
     * in the context's current block is 56 bytes
     */
    if (ctx->bytes_in_block < 56) {
        num_to_append = 56 - ctx->bytes_in_block;
    }
    else {
        num_to_append = SHA1_BLOCK_BYTES - (ctx->bytes_in_block - 56);
    }
    to_append[0] = (byte)(0x80);
    memset(to_append + 1, 0, num_to_append - 1);

    /*
     * Place the number of bits processed prior to this function being called
     * into the context (as a 64-bit integer in big endian order), filling out
     * the current block.
     */
    put_big_end_64(to_append + num_to_append, total_bits);

    /* Append and finalize */
    sha1_add(ctx, to_append, num_to_append + 8);
    for (i = 0; i < 5; i++) {
        put_big_end_32(digest + i * 4, ctx->h[i]);
    }
    return 0;
}

void sha1_copy(struct sha1_ctx *dst, const struct sha1_ctx *src)
{
    memcpy(dst, src, sizeof(struct sha1_ctx));
}

void sha1_free_scrub(struct sha1_ctx *ctx)
{
    if (ctx != NULL) {
        scrub_memory(ctx, sizeof(struct sha1_ctx));
        free(ctx);
    }
}

static void sha1_process_block(struct sha1_ctx *ctx, const byte *block)
{
    uint32_t a = ctx->h[0];
    uint32_t b = ctx->h[1];
    uint32_t c = ctx->h[2];
    uint32_t d = ctx->h[3];
    uint32_t e = ctx->h[4];
    uint32_t w[80];
    uint32_t f, k, temp;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = get_big_end_32(block + i * 4);
    }
    for (i = 16; i < 80; i++) {
        w[i] =
            circ_shift_left_32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = (uint32_t)0x5A827999;
        }
        else if (i < 40) {
            f = b ^ c ^ d;
            k = (uint32_t)0x6ED9EBA1;
        }
        else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = (uint32_t)0x8F1BBCDC;
        }
        else {
            f = b ^ c ^ d;
            k = (uint32_t)0xCA62C1D6;
        }

        temp = circ_shift_left_32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = circ_shift_left_32(b, 30);
        b = a;
        a = temp;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
}

static int add_num_bytes(struct sha1_ctx *ctx, size_t num_bytes)
{
    if (ctx->bytes_exceeded) {
        return -1;
    }
    if (addition_would_overflow_u64(ctx->bytes_processed, num_bytes)) {
        ctx->bytes_exceeded = true;
        return -1;
    }

    ctx->bytes_processed = ctx->bytes_processed + (uint64_t)num_bytes;
    if (ctx->bytes_processed > SHA1_MAX_MESSAGE_BYTES) {
        ctx->bytes_exceeded = true;
        return -1;
    }
    return 0;
}

static bool addition_would_overflow_u64(uint64_t a, size_t b)
{
#if SIZE_MAX > UINT64_MAX
    if (b > (size_t)UINT64_MAX) {
        return true;
    }
#endif
    return (UINT64_MAX - (uint64_t)b < a);
}
