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

/*
 * The maximal output size of any supported HMAC algorithm. The output size of
 * an HMAC operation is the same as the output size of the underlying hash
 * function.
 */
#define HMAC_MAX_DIGEST_BYTES (CHF_MAX_DIGEST_SIZE)

/*
 * The error codes that can be returned by hmac_start(), hmac_add(), and
 * hmac_end(). These represent if the key provided to the HMAC in hmac_start()
 * is too long, or if the message provided with hmac_add() is too long. The
 * error that the key is too long takes precedence over the error that the
 * message is too long.
 */
#define HMAC_ERROR_KEY_TOO_LONG     (-1)
#define HMAC_ERROR_MESSAGE_TOO_LONG (-2)

/*
 * Opaque HMAC context.
 */
struct hmac_ctx;

/*
 * Allocates a new context for an HMAC function, with the argument being the
 * algorithm of the underlying cryptographic hash function. Must be freed with
 * hmac_free_scrub(). Guaranteed to return non-NULL; it is a fatal error for
 * allocation to fail, or for alg to be a value other than a supported
 * algorithm.
 */
struct hmac_ctx *hmac_alloc(chf_algorithm alg);

/*
 * Starts a new HMAC operation with the given context. The size of the key is
 * given in bytes. Returns 0 on success or a negative value (specifically
 * HMAC_ERROR_KEY_TOO_LONG) if the provided key is too long for the underlying
 * cryptographic hash function to process.
 */
int hmac_start(struct hmac_ctx *hmac, const byte *key, size_t keyLen);

/*
 * Updates the HMAC context with the given bytes. Returns 0 on success, or a
 * negative value on error, specifically: HMAC_ERROR_KEY_TOO_LONG if the key
 * provided to hmac_start() was too long, or HMAC_ERROR_MESSAGE_TOO_LONG if the
 * key provided to hmac_start() was okay but the bytes provided to hmac_add()
 * have caused the underlying cryptographic hash function's maximum message
 * length to be exceeded.
 *
 * It is a fatal error if an HMAC operation has not been started with
 * hmac_start().
 */
int hmac_add(struct hmac_ctx *hmac, const byte *bytes, size_t numBytes);

/*
 * Computes the HMAC of the key and data that have been provided and writes the
 * result to the digest array. The amount of data written will be equal to
 * hmac_digest_bytes(), which is guaranteed not to exceed
 * HMAC_MAX_DIGEST_BYTES.
 *
 * Returns 0 on success, or a negative value on error, specifically:
 * HMAC_ERROR_KEY_TOO_LONG if the key provided to hmac_start() was too long, or
 * HMAC_ERROR_MESSAGE_TOO_LONG if the key provided to hmac_start() was okay but
 * the message provided to hmac_add() was too long.
 *
 * It is a fatal error if an HMAC operation has not been started with
 * hmac_start().
 */
int hmac_end(struct hmac_ctx *hmac, byte *digest);

/*
 * A shorthand for calling hmac_start(), then a single hmac_add(), then
 * hmac_end(). Has the same return value as hmac_end(). Because the underlying
 * functions are called in sequence, you may use the same memory location for
 * the source bytes and the output digest.
 */
int hmac_single(struct hmac_ctx *hmac, const byte *key, size_t keyLen,
                const byte *bytes, size_t numBytes, byte *digest);

/*
 * Returns the size of the HMAC output in bytes, which is guaranteed to be
 * greater than zero and no larger than HMAC_MAX_DIGEST_BYTES.
 */
size_t hmac_digest_size(const struct hmac_ctx *hmac);

/*
 * Copies the current content of the src context into the dst context. This
 * function is equivalent to running the same sequence of operations (e.g.,
 * hmac_start(), hmac_add(), etc.) on dst that have, so far, been run on src
 * (but copying is typically much cheaper computationally).
 *
 * The two contexts must be of the same algorithm, otherwise a fatal error
 * occurs. Calling with src == dst is a no-op.
 */
void hmac_copy(struct hmac_ctx *dst, const struct hmac_ctx *src);

/*
 * Frees an HMAC context allocated with hmac_alloc(), and securely scrubs all
 * memory allocated for the context. Calling with NULL is a no-op.
 */
void hmac_free_scrub(struct hmac_ctx *hmac);

#endif
