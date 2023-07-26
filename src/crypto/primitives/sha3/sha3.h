/*
 * Copyright (c) 2013-2023 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_CRYPTO_PRIMITIVES_SHA3_SHA3_H_
#define PISCES_CRYPTO_PRIMITIVES_SHA3_SHA3_H_

#include "common/bytetype.h"

#include <stddef.h>

/*
 * The number of bytes output by the SHA-3 variants.
 */
#define SHA3_224_DIGEST_BYTES (28)
#define SHA3_256_DIGEST_BYTES (32)
#define SHA3_384_DIGEST_BYTES (48)
#define SHA3_512_DIGEST_BYTES (64)

/*
 * The number of bytes processed at once by the SHA-3 variants.
 */
#define SHA3_224_BLOCK_BYTES (144)
#define SHA3_256_BLOCK_BYTES (136)
#define SHA3_384_BLOCK_BYTES (104)
#define SHA3_512_BLOCK_BYTES (72)

/*
 * Opaque SHA-3 context. Note that there are undefined behaviours, described
 * below, with this opaque structure.
 */
struct sha3_ctx;

/*
 * Allocates a new SHA-3 context. Must be freed with sha3_free() or
 * sha3_free_scrub(). Guaranteed to return non-NULL; it is a fatal error if
 * allocation fails.
 *
 * Does not automatically call sha3_*_start(), so sha3_*_start() or sha3_copy()
 * should be called after allocation.
 */
struct sha3_ctx *sha3_alloc(void);

/*
 * Starts a new SHA-3 operation. The sha3_end() function will return undefined
 * results if one of the sha3_*_start() functions, or sha3_copy() with a
 * running source, is not called.
 */
void sha3_224_start(struct sha3_ctx *ctx);
void sha3_256_start(struct sha3_ctx *ctx);
void sha3_384_start(struct sha3_ctx *ctx);
void sha3_512_start(struct sha3_ctx *ctx);

/*
 * Adds the given data to the input stream processed by the SHA-3 context.
 */
void sha3_add(struct sha3_ctx *ctx, const byte_t *bytes, size_t numBytes);

/*
 * Computes the SHA-3 hash of the message. The output of this function is
 * undefined if one of the sha3_*_start() functions has not been called.
 */
void sha3_end(struct sha3_ctx *ctx, byte_t *digest);

/*
 * Copies the current state of the src context into the dst context. Behaviour
 * is underfined if the contexts overlap. Both contexts must first be allocated
 * by sha3_alloc().
 */
void sha3_copy(struct sha3_ctx *dst, const struct sha3_ctx *src);

/*
 * Frees a SHA-3 context allocated with sha3_alloc(), and securely scrubs all
 * memory allocated for the context. Calling with NULL is a no-op.
 */
void sha3_free_scrub(struct sha3_ctx *ctx);

#endif
