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

#ifndef PISCES_CRYPTO_PRIMITIVES_BLAKE2B_BLAKE2B_H_
#define PISCES_CRYPTO_PRIMITIVES_BLAKE2B_BLAKE2B_H_

#include "common/bytetype.h"

#include <stddef.h>

#define BLAKE2B_BLOCK_BYTES      (128)
#define BLAKE2B_MAX_DIGEST_BYTES (64)
#define BLAKE2B_MAX_KEY_BYTES    (64)

struct blake2b_ctx;

/*
 * Allocates a new BLAKE2b context. Must be freed with blake2b_free_scrub().
 * Guaranteed to return non-NULL. Does not automatically call blake2b_start().
 */
struct blake2b_ctx *blake2b_alloc(void);

/*
 * Starts a new BLAKE2b operation. Use key_len == 0 for an unkeyed hash, in
 * which case key may be NULL.
 */
void blake2b_start(struct blake2b_ctx *ctx, size_t digest_len, const byte *key,
                   size_t key_len);

/*
 * Adds the given data to the input stream processed by the BLAKE2b context.
 * Returns 0 on success or -1 if the message size has exceeded the maximum
 * BLAKE2b message length.
 */
int blake2b_add(struct blake2b_ctx *ctx, const byte *bytes, size_t num_bytes);

/*
 * Computes the BLAKE2b hash of the message. Guaranteed to succeed if the
 * maximum message size has not been exceeded. Returns 0 if it succeeds, or -1
 * if the message size has exceeded the maximum BLAKE2b message length. The
 * output of this function is undefined if blake2b_start() has not been called.
 */
int blake2b_end(struct blake2b_ctx *ctx, byte *digest);

/*
 * Copies the current state of the src context into the dst context. Behaviour
 * is underfined if the contexts overlap. Both contexts must first be allocated
 * by blake2b_alloc().
 */
void blake2b_copy(struct blake2b_ctx *dst, const struct blake2b_ctx *src);

/*
 * Frees a BLAKE2b context allocated with blake2b_alloc(), and securely scrubs
 * all memory allocated for the context. Calling with NULL is a no-op.
 */
void blake2b_free_scrub(struct blake2b_ctx *ctx);

#endif
