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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define SHA1_MAX_MESSAGE_BYTES ((uint64_t)(0x1FFFFFFFFFFFFFFFLLU))

struct sha1_ctx {
    uint32_t h[5];
    uint64_t bytesProcessed;
    byte block[SHA1_BLOCK_BYTES];
    uint8_t bytesInBlock;
    int bytesExceeded;
};

/*
 * Process a single block of data into the SHA-1 context. Assumes the number
 * of bytes processed, including the given block, does not exceed the maximum
 * message length of SHA-1.
 */
static void sha1_process_block(struct sha1_ctx *ctx, const byte *block);

/*
 * Adds the given number of bytes to the context's count of bytes processed.
 * Returns 0 on success, or -1 if the maximum message size is exceeded
 * (including if it overflows). If the maximum message size is exceeded, the
 * bytesExceeded flag is set in the context, and all subsequent calls to this
 * function will return -1.
 */
static int add_num_bytes(struct sha1_ctx *ctx, size_t numBytes);

/*
 * Returns 1 if the addition of a and b (with b cast to a uint64_t), would
 * overflow a uint64_t result. If not, returns 0.
 */
static int addition_would_overflow_u64(uint64_t a, size_t b);

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
    ctx->bytesProcessed = 0;
    ctx->bytesInBlock = 0;
    ctx->bytesExceeded = 0;
}

int sha1_add(struct sha1_ctx *ctx, const byte *bytes, size_t numBytes)
{
    size_t toFillBlock, addToCtx;

    /* Update the number of bytes processed by the context */
    if (add_num_bytes(ctx, numBytes)) {
        return -1;
    }

    /* Process the data in blocks */
    while (numBytes > 0) {
        if (ctx->bytesInBlock == 0 && numBytes >= SHA1_BLOCK_BYTES) {
            sha1_process_block(ctx, bytes);
            bytes += SHA1_BLOCK_BYTES;
            numBytes -= SHA1_BLOCK_BYTES;
        }
        else {
            toFillBlock = SHA1_BLOCK_BYTES - ctx->bytesInBlock;
            addToCtx = MIN(toFillBlock, numBytes);
            memcpy(ctx->block + ctx->bytesInBlock, bytes, addToCtx);
            ctx->bytesInBlock += addToCtx;
            bytes += addToCtx;
            numBytes -= addToCtx;
            if (ctx->bytesInBlock == SHA1_BLOCK_BYTES) {
                ctx->bytesInBlock = 0;
                sha1_process_block(ctx, ctx->block);
            }
        }
    }

    return 0;
}

int sha1_end(struct sha1_ctx *ctx, byte *digest)
{
    byte toAppend[SHA1_BLOCK_BYTES + 8];
    uint64_t totalBits;
    size_t numToAppend;
    int i;

    if (ctx->bytesExceeded) {
        return -1;
    }

    totalBits = ctx->bytesProcessed * 8;

    /*
     * Append 0x80 0x00 0x00 0x00 ... 0x00 so that the resulting amount of data
     * in the context's current block is 56 bytes
     */
    if (ctx->bytesInBlock < 56) {
        numToAppend = 56 - ctx->bytesInBlock;
    }
    else {
        numToAppend = SHA1_BLOCK_BYTES - (ctx->bytesInBlock - 56);
    }
    toAppend[0] = (byte)(0x80);
    memset(toAppend + 1, 0, numToAppend - 1);

    /*
     * Place the number of bits processed prior to this function being called
     * into the context (as a 64-bit integer in big endian order), filling out
     * the current block.
     */
    put_big_end_64(toAppend + numToAppend, totalBits);

    /* Append and finalize */
    sha1_add(ctx, toAppend, numToAppend + 8);
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

static int add_num_bytes(struct sha1_ctx *ctx, size_t numBytes)
{
    if (ctx->bytesExceeded) {
        return -1;
    }
    if (addition_would_overflow_u64(ctx->bytesProcessed, numBytes)) {
        ctx->bytesExceeded = 1;
        return -1;
    }

    ctx->bytesProcessed = ctx->bytesProcessed + (uint64_t)numBytes;
    if (ctx->bytesProcessed > SHA1_MAX_MESSAGE_BYTES) {
        ctx->bytesExceeded = 1;
        return -1;
    }
    return 0;
}

static int addition_would_overflow_u64(uint64_t a, size_t b)
{
#if SIZE_MAX > UINT64_MAX
    if (b > (size_t)UINT64_MAX) {
        return 1;
    }
#endif
    return (UINT64_MAX - (uint64_t)b < a);
}
