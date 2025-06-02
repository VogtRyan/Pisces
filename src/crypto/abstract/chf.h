/*
 * Copyright (c) 2008-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_CRYPTO_ABSTRACT_CHF_H_
#define PISCES_CRYPTO_ABSTRACT_CHF_H_

#include "common/bytetype.h"

#include <stddef.h>

#define CHF_MAX_DIGEST_BYTES (64)
#define CHF_MAX_BLOCK_BYTES  (144)

typedef enum { CHF_ALG_SHA1, CHF_ALG_SHA3_512 } chf_algorithm_t;

#define CHF_ERROR_MESSAGE_TOO_LONG (-1)

struct chf_ctx;

/*
 * Allocates a new context for a cryptographic hash function. Does not
 * automatically start a new hash operation. Must be freed with
 * chf_free_scrub(). Guaranteed to return non-NULL.
 */
struct chf_ctx *chf_alloc(chf_algorithm_t alg);

/*
 * Starts a new hash operation with the given context, clearing any input data
 * already processed.
 */
void chf_start(struct chf_ctx *chf);

/*
 * Adds the given input bytes to the stream of data being hashed. Returns 0 on
 * success, <0 on error (CHF_ERROR_MESSAGE_TOO_LONG).
 */
int chf_add(struct chf_ctx *chf, const byte_t *input, size_t inputLen);

/*
 * Computes the message digest of the data that has been provided. The amount
 * of data written will be equal to chf_digest_bytes(), which is guaranteed
 * not to exceed CHF_MAX_DIGEST_BYTES. Returns 0 on success, <0 on error
 * (CHF_ERROR_MESSAGE_TOO_LONG).
 */
int chf_end(struct chf_ctx *chf, byte_t *output);

/*
 * Calls chf_start(), chf_add(), then chf_end() in sequence. Because the
 * underlying functions are called in sequence, you may use the same memory
 * location for the input bytes and the output digest. Returns 0 on success, <0
 * on error (CHF_ERROR_MESSAGE_TOO_LONG).
 */
int chf_single(struct chf_ctx *chf, const byte_t *input, size_t inputLen,
               byte_t *output);

/*
 * Returns the size of the message digest output in bytes, which is guaranteed
 * to be greater than zero and no larger than CHF_MAX_DIGEST_BYTES.
 */
size_t chf_digest_size(const struct chf_ctx *chf);

/*
 * Returns the block size of the cryptographic hash algorithm in bytes, which
 * is guaranteed to be greater than zero and no larger than
 * CHF_MAX_BLOCK_BYTES. Typically used only for building other cryptographic
 * algorithms on top of a cryptographic hash primitive.
 */
size_t chf_block_size(const struct chf_ctx *chf);

/*
 * Copies the current content of the src context into the dst context, which
 * must be running the same hash algorithm. This function is equivalent to
 * running the same sequence of operations (e.g., chf_start(), chf_add(), etc.)
 * on dst that have, so far, been run on src (but copying is typically much
 * cheaper computationally). Calling with src == dst is a no-op.
 */
void chf_copy(struct chf_ctx *dst, const struct chf_ctx *src);

/*
 * Returns a human-readable description of the most recent outcome of
 * chf_start(), chf_add(), or chf_end().
 */
const char *chf_error(const struct chf_ctx *chf);

/*
 * Frees a context allocated with chf_alloc(), and securely scrubs all memory
 * allocated for the context. Calling with NULL is a no-op.
 */
void chf_free_scrub(struct chf_ctx *chf);

#endif
