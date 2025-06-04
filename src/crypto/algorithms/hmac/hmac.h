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

#ifndef PISCES_CRYPTO_ALGORITHMS_HMAC_HMAC_H_
#define PISCES_CRYPTO_ALGORITHMS_HMAC_HMAC_H_

#include "common/bytetype.h"
#include "crypto/abstract/chf.h"

#include <stddef.h>

#define HMAC_MAX_DIGEST_SIZE (CHF_MAX_DIGEST_SIZE)

#define HMAC_ERROR_KEY_TOO_LONG     (-1)
#define HMAC_ERROR_MESSAGE_TOO_LONG (-2)

struct hmac_ctx;

/*
 * Allocates a new context for an HMAC function. Must be freed with
 * hmac_free_scrub(). Guaranteed to return non-NULL.
 */
struct hmac_ctx *hmac_alloc(chf_algorithm alg);

/*
 * Starts a new HMAC operation, clearing any input data already processed.
 * Returns 0 on success, <0 on error (HMAC_ERROR_KEY_TOO_LONG).
 */
int hmac_start(struct hmac_ctx *hmac, const byte *key, size_t keyLen);

/*
 * Appends the given input data to the message being authenticated. Returns 0
 * on success, <0 on error (in order of precedence from highest to lowest:
 * HMAC_ERROR_KEY_TOO_LONG, HMAC_ERROR_MESSAGE_TOO_LONG).
 */
int hmac_add(struct hmac_ctx *hmac, const byte *bytes, size_t numBytes);

/*
 * Computes the HMAC digest of the message. The size of the HMAC will be equal
 * to hmac_digest_size(), which is guaranteed not to exceed
 * HMAC_MAX_DIGEST_SIZE. Returns 0 on success, <0 on error (in order of
 * precedence from highest to lowest: HMAC_ERROR_KEY_TOO_LONG,
 * HMAC_ERROR_MESSAGE_TOO_LONG).
 */
int hmac_end(struct hmac_ctx *hmac, byte *digest);

/*
 * Calls hmac_start(), hmac_add(), then hmac_end(). Because the underlying
 * functions are called in sequence, the buffers may overlap. Returns the same
 * value as hmac_end().
 */
int hmac_single(struct hmac_ctx *hmac, const byte *key, size_t keyLen,
                const byte *bytes, size_t numBytes, byte *digest);

/*
 * Returns the size of the HMAC digest in bytes. Guaranteed to be greater than
 * zero and no larger than HMAC_MAX_DIGEST_SIZE. The digest size of the HMAC
 * is equal to the digest size of the underlying cryptographic hash function.
 */
size_t hmac_digest_size(const struct hmac_ctx *hmac);

/*
 * Copies the current content of the src context into the dst context, which
 * must be using the same underlying chf_algorithm. Copying the context is
 * equivalent to running the same sequence of operations (e.g., hmac_start(),
 * hmac_add(), etc.) on dst that have been run so far on src, but in constant
 * time. Calling with src == dst is a no-op.
 */
void hmac_copy(struct hmac_ctx *dst, const struct hmac_ctx *src);

/*
 * Frees an HMAC context allocated with hmac_alloc() and securely scrubs all
 * memory allocated for the context. Calling with NULL is a no-op.
 */
void hmac_free_scrub(struct hmac_ctx *hmac);

#endif
