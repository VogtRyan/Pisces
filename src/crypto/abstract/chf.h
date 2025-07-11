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

#define CHF_MAX_BLOCK_SIZE  (144)
#define CHF_MAX_DIGEST_SIZE (64)

#define CHF_ERROR_MESSAGE_TOO_LONG (-1)

typedef enum { CHF_ALG_SHA1, CHF_ALG_SHA3_512 } chf_algorithm;

struct chf_ctx;

/*
 * Allocates a new context for a cryptographic hash function. Does not
 * automatically start a new hash operation. Must be freed with
 * chf_free_scrub(). Guaranteed to return non-NULL.
 */
struct chf_ctx *chf_alloc(chf_algorithm alg);

/*
 * Starts a new hash operation, clearing any message data already processed.
 */
void chf_start(struct chf_ctx *chf);

/*
 * Appends the given bytes to the message being hashed. Returns 0 on success,
 * <0 on error (CHF_ERROR_MESSAGE_TOO_LONG).
 */
int chf_add(struct chf_ctx *chf, const byte *msg, size_t msg_len);

/*
 * Computes the message digest. The size of the digest will be equal to
 * chf_digest_size(), which is guaranteed not to exceed CHF_MAX_DIGEST_SIZE.
 * Returns 0 on success, <0 on error (CHF_ERROR_MESSAGE_TOO_LONG).
 */
int chf_end(struct chf_ctx *chf, byte *digest);

/*
 * Calls chf_start(), chf_add(), then chf_end(). Because the underlying
 * functions are called in sequence, the buffers may overlap. Returns the same
 * value as chf_end().
 */
int chf_single(struct chf_ctx *chf, const byte *msg, size_t msg_len,
               byte *digest);

/*
 * Returns the size of the hash algorithm's digest output. Guaranteed to be
 * greater than zero and no larger than CHF_MAX_DIGEST_SIZE.
 */
size_t chf_digest_size(const struct chf_ctx *chf);

/*
 * Returns the hash algorithm's block size. Guaranteed to be greater than zero
 * and no larger than CHF_MAX_BLOCK_SIZE. Typically used only for building
 * other cryptographic algorithms on top of a cryptographic hash primitive.
 */
size_t chf_block_size(const struct chf_ctx *chf);

/*
 * Copies the current content of the src context into the dst context, which
 * must be using the same chf_algorithm. Copying the context is equivalent to
 * running the same sequence of operations (e.g., chf_start(), chf_add(), etc.)
 * on dst that have been run so far on src, but in constant time. Calling with
 * src == dst is a no-op.
 */
void chf_copy(struct chf_ctx *dst, const struct chf_ctx *src);

/*
 * Returns a human-readable description of the most recent outcome of
 * chf_start(), chf_add(), or chf_end().
 */
const char *chf_error(const struct chf_ctx *chf);

/*
 * Frees a context allocated with chf_alloc() and securely scrubs all memory
 * allocated for the context. Calling with NULL is a no-op.
 */
void chf_free_scrub(struct chf_ctx *chf);

#endif
