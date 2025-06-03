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

#ifndef PISCES_CRYPTO_PRIMITIVES_SHA1_SHA1_H_
#define PISCES_CRYPTO_PRIMITIVES_SHA1_SHA1_H_

#include "common/bytetype.h"

#include <stddef.h>

/*
 * The number of bytes output in a SHA-1 hash, and the internal block size of
 * SHA-1.
 */
#define SHA1_DIGEST_BYTES (20)
#define SHA1_BLOCK_BYTES  (64)

/*
 * Opaque SHA-1 context. Note that there are undefined behaviours, described
 * below, with this opaque structure.
 */
struct sha1_ctx;

/*
 * Allocates a new SHA-1 context. Must be freed with sha1_free() or
 * sha1_free_scrub(). Guaranteed to return non-NULL; it is a fatal error for
 * allocation to fail.
 *
 * Does not automatically call sha1_start(), so sha1_start() or sha1_copy()
 * should be called after allocation.
 */
struct sha1_ctx *sha1_alloc(void);

/*
 * Starts a new SHA-1 operation. The sha1_end() function will return undefined
 * results if sha1_start(), or sha1_copy() with a running source, is not
 * called.
 */
void sha1_start(struct sha1_ctx *ctx);

/*
 * Adds the given data to the input stream processed by the SHA-1 context.
 * Returns 0 on success or -1 if the message size has exceeded the maximum
 * SHA-1 message length.
 */
int sha1_add(struct sha1_ctx *ctx, const byte *bytes, size_t numBytes);

/*
 * Computes the SHA-1 hash of the message. Guaranteed to succeed if the maximum
 * message size has not been exceeded. Returns 0 if it succeeds, or -1 if the
 * message size has exceeded the maximum SHA-1 message length. The output of
 * this function is undefined if sha1_start() has not been called.
 */
int sha1_end(struct sha1_ctx *ctx, byte *digest);

/*
 * Copies the current state of the src context into the dst context. Behaviour
 * is underfined if the contexts overlap. Both contexts must first be allocated
 * by sha1_alloc().
 */
void sha1_copy(struct sha1_ctx *dst, const struct sha1_ctx *src);

/*
 * Frees a SHA-1 context allocated with sha1_alloc(), and securely scrubs all
 * memory allocated for the context. Calling with NULL is a no-op.
 */
void sha1_free_scrub(struct sha1_ctx *ctx);

#endif
