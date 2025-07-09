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

#ifndef PISCES_CRYPTO_ABSTRACT_CIPHER_H_
#define PISCES_CRYPTO_ABSTRACT_CIPHER_H_

#include "common/bytetype.h"

#include <stddef.h>
#include <stdint.h>

#define CIPHER_MAX_BLOCK_SIZE (16)
#define CIPHER_MAX_IV_SIZE    (16)
#define CIPHER_MAX_KEY_SIZE   (32)

#define CIPHER_ADD_MAX_INPUT_LEN (SIZE_MAX - CIPHER_MAX_BLOCK_SIZE + 1)

#define CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE (-1)
#define CIPHER_ERROR_NO_BLOCK_TO_DEPAD             (-2)
#define CIPHER_ERROR_INVALID_PAD_DATA              (-3)

typedef enum {
    CIPHER_ALG_AES_128_CBC_NOPAD,
    CIPHER_ALG_AES_128_CBC_PKCS7PAD,
    CIPHER_ALG_AES_256_CBC_NOPAD,
    CIPHER_ALG_AES_256_CBC_PKCS7PAD
} cipher_algorithm;

typedef enum {
    CIPHER_DIRECTION_ENCRYPT,
    CIPHER_DIRECTION_DECRYPT
} cipher_direction;

struct cipher_ctx;

/*
 * Allocates a new context for a cipher operation. Must be freed with
 * cipher_free_scrub(). Guaranteed to return non-NULL.
 */
struct cipher_ctx *cipher_alloc(cipher_algorithm alg);

/*
 * Sets whether the context encrypts or decrypts. Must be called prior to
 * starting a cipher operation.
 */
void cipher_set_direction(struct cipher_ctx *cipher,
                          cipher_direction direction);

/*
 * Sets the encryption key. Must be called prior to starting a cipher
 * operation. The key must be exactly cipher_key_size() bytes, which is
 * guaranteed to be no larger than CIPHER_MAX_KEY_SIZE.
 */
void cipher_set_key(struct cipher_ctx *cipher, const byte *key);

/*
 * Sets the initialization vector. Must be called prior to starting a cipher
 * operation. The IV must be exactly cipher_iv_size() bytes, which is
 * guaranteed to be no larger than CIPHER_MAX_IV_SIZE.
 *
 * This IV will be used for all newly started cipher operations. That is,
 * starting a new cipher operation will always reset the context's IV to this
 * value.
 */
void cipher_set_iv(struct cipher_ctx *cipher, const byte *iv);

/*
 * Starts a new cipher operation using the parameters set with
 * cipher_set_direction(), cipher_set_key(), and cipher_set_iv().
 */
void cipher_start(struct cipher_ctx *cipher);

/*
 * Encrypts or decrypts the given data. The input can be at most
 * CIPHER_ADD_MAX_INPUT_LEN bytes long.
 *
 * The number of output bytes is guaranteed to be between 0 and input_len+b-1,
 * inclusive, where b is the block size of the cipher (itself guaranteed to be
 * no larger than CIPHER_MAX_BLOCK_SIZE). The computation input_len+b-1 is
 * guaranteed to fit in a size_t, assuming input_len is at most
 * CIPHER_ADD_MAX_INPUT_LEN.
 */
void cipher_add(struct cipher_ctx *cipher, const byte *input, size_t input_len,
                byte *output, size_t *output_len);

/*
 * Finalizes the encryption or decryption operation. The number of output
 * bytes is guaranteed to be between 0 and b, where b is the block size of the
 * cipher (itself guaranteed to be no larger than CIPHER_MAX_BLOCK_SIZE).
 *
 * Returns 0 on success, <0 on error. In order of precedence from highest to
 * lowest, possible error returns are:
 *
 * - CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE, for encryption with unpadded
 *   ciphers or decryption with any cipher, when the total input length is not
 *   a multiple of block size;
 *
 * - CIPHER_ERROR_NO_BLOCK_TO_DEPAD, for decryption with padded ciphers, when
 *   there is no last block to depad; and,
 *
 * - CIPHER_ERROR_INVALID_PAD_DATA, for decryption with padded ciphers, when
 *   the last block's padding bytes are corrupt.
 */
int cipher_end(struct cipher_ctx *cipher, byte *output, size_t *output_len);

/*
 * Returns the block size of the cipher. Guaranteed to be greater than zero and
 * no larger than CIPHER_MAX_BLOCK_SIZE.
 */
size_t cipher_block_size(const struct cipher_ctx *cipher);

/*
 * Returns the size of the initialization vector for the cipher. Guaranteed to
 * be greater than zero and no larger than CIPHER_MAX_IV_SIZE.
 */
size_t cipher_iv_size(const struct cipher_ctx *cipher);

/*
 * Returns the key size of the cipher. Guaranteed to be greater than zero and
 * no larger than CIPHER_MAX_KEY_SIZE.
 */
size_t cipher_key_size(const struct cipher_ctx *cipher);

/*
 * Returns a human-readable description of the most recent outcome of
 * cipher_end().
 */
const char *cipher_error(const struct cipher_ctx *cipher);

/*
 * Frees a cipher context allocated with cipher_alloc() and securely scrubs
 * all memory allocated for the context. Calling with NULL is a no-op.
 */
void cipher_free_scrub(struct cipher_ctx *cipher);

#endif
