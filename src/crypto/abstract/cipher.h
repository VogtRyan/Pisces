/*
 * Copyright (c) 2008-2023 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_CRYPTO_ABSTRACT_CIPHER_H_
#define PISCES_CRYPTO_ABSTRACT_CIPHER_H_

#include "common/bytetype.h"

#include <stddef.h>
#include <stdint.h>

/*
 * The maximal key size, block size, and IV size for any supported cipher in
 * this header.
 */
#define CIPHER_MAX_BLOCK_BYTES (16)
#define CIPHER_MAX_IV_BYTES (16)
#define CIPHER_MAX_KEY_BYTES (32)

/*
 * Supported cipher algorithms.
 */
typedef enum {
    CIPHER_ALG_AES_128_CBC_NOPAD,
    CIPHER_ALG_AES_128_CBC_PKCS7PAD,
    CIPHER_ALG_AES_256_CBC_NOPAD,
    CIPHER_ALG_AES_256_CBC_PKCS7PAD
} cipher_algorithm_t;

/*
 * Directions a cipher operation can procced.
 */
typedef enum {
    CIPHER_DIRECTION_ENCRYPT,
    CIPHER_DIRECTION_DECRYPT
} cipher_direction_t;

/*
 * The maximum size of the input data that can be provided to cipher_add().
 */
#define CIPHER_ADD_MAX_INPUT_SIZE (SIZE_MAX - CIPHER_MAX_BLOCK_BYTES + 1)

/*
 * The errors that can be returned by cipher_end(). The errors about the input
 * size not being correct take precedence over the pad data itself being
 * invalid.
 */
#define CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE (-1)
#define CIPHER_ERROR_NO_BLOCK_TO_DEPAD (-2)
#define CIPHER_ERROR_INVALID_PAD_DATA (-3)

/*
 * Opaque cipher context.
 */
struct cipher_ctx;

/*
 * Allocates a new context for a cipher operation. Must be freed with
 * cipher_free_scrub(). Guaranteed to return non-NULL; it is a fatal error for
 * allocation to fail, or for alg to be a value other than a supported
 * algorithm.
 */
struct cipher_ctx *cipher_alloc(cipher_algorithm_t alg);

/*
 * Sets the direction in which a cipher operation performed by the context will
 * proceed. It is a fatal error for this function to be called on a running
 * context or with an invalid direction.
 */
void cipher_set_direction(struct cipher_ctx *cipher,
                          cipher_direction_t direction);

/*
 * Sets the key that the a cipher operation performed by the context will use.
 * The key must be exactly cipher_key_size() bytes, which is guaranteed to be
 * no larger than CIPHER_MAX_KEY_BYTES. It is a fatal error for this function
 * to be called on a running cipher.
 */
void cipher_set_key(struct cipher_ctx *cipher, const byte_t *key);

/*
 * Sets the initialization vector that a cipher operation performed by the
 * context will use. The IV must be exactly cipher_iv_size() bytes, which is
 * guaranteed to be no larger than CIPHER_MAX_IV_BYTES. It is a fatal error for
 * this function to be called on a running cipher.
 *
 * Note that the execution of a cipher operation does not change the starting
 * initialization vector for future operations. That is, calling
 * cipher_set_iv(), followed by cipher_start(), cipher_add(), cipher_end(),
 * then cipher_start() again, will result in two operations that use the same
 * IV.
 */
void cipher_set_iv(struct cipher_ctx *cipher, const byte_t *iv);

/*
 * Starts a new cipher operation with the given context. It is a fatal error to
 * attempt to start an operation without having called all of
 * cipher_set_direction(), cipher_set_key(), and cipher_set_iv().
 */
void cipher_start(struct cipher_ctx *cipher);

/*
 * Encrypts or decrypts the given data and places any resulting bytes into
 * the output buffer. The number of bytes placed into the buffer will be placed
 * in outputBytes, if outputBytes is non-NULL.
 *
 * The number of output bytes is guaranteed to be between 0 and numBytes+b-1,
 * inclusive, where b is the block size of the cipher (which is itself
 * guaranteed to be no larger than CIPHER_MAX_BLOCK_BYTES).
 *
 * It is a fatal error for the number of input bytes to exceed
 * CIPHER_ADD_MAX_INPUT_SIZE. That bound guarantees the computation of
 * numBytes+b-1 will not overflow. It is a fatal error for this function to be
 * called on a non-running cipher.
 */
void cipher_add(struct cipher_ctx *cipher, const byte_t *bytes,
                size_t numBytes, byte_t *output, size_t *outputBytes);

/*
 * Finalizes the encryption or decryption operation, placing any last output
 * into the output buffer. The number of bytes placed into the buffer will be
 * stored in outputBytes, if outputBytes is non-NULL.
 *
 * The number of output bytes is guaranteed to be between 0 and b, where b is
 * the block size of the cipher (which is itself guaranteed to be no larger
 * than CIPHER_MAX_BLOCK_BYTES).
 *
 * Returns 0 on success, or a negative number (specifically
 * CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE, CIPHER_ERROR_NO_BLOCK_TO_DEPAD,
 * or CIPHER_ERROR_INVALID_PAD_DATA) and sets the value of outputBytes to zero
 * if there is an error. It is a fatal error for this function to be called on
 * a non-running cipher.
 */
int cipher_end(struct cipher_ctx *cipher, byte_t *output, size_t *outputBytes);

/*
 * Returns the block size of the cipher, which is guaranteed to be no larger
 * than CIPHER_MAX_BLOCK_BYTES.
 */
size_t cipher_block_size(const struct cipher_ctx *cipher);

/*
 * Returns the size of the initialization vector for the cipher, which is
 * guaranteed to be no larger than CIPHER_MAX_IV_BYTES.
 */
size_t cipher_iv_size(const struct cipher_ctx *cipher);

/*
 * Returns the key size of the cipher, which is guaranteed to be no larger than
 * CIPHER_MAX_KEY_BYTES.
 */
size_t cipher_key_size(const struct cipher_ctx *cipher);

/*
 * Returns a human-readable description of the error returned by cipher_end().
 */
const char *cipher_error(const struct cipher_ctx *cipher);

/*
 * Frees a cipher context allocated with cipher_alloc(), and securely scrubs
 * all memory allocated for the context. Calling with NULL is a no-op.
 */
void cipher_free_scrub(struct cipher_ctx *cipher);

#endif
