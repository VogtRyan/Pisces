/*
 * Copyright (c) 2023-2024 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_CRYPTO_PRIMITIVES_AES_AES_CBC_H_
#define PISCES_CRYPTO_PRIMITIVES_AES_AES_CBC_H_

#include "common/bytetype.h"

#include <stddef.h>

/*
 * Possible key sizes, equal to the number of bytes in the key.
 */
#define AES_CBC_KEY_SIZE_128 (16)
#define AES_CBC_KEY_SIZE_192 (24)
#define AES_CBC_KEY_SIZE_256 (32)
#define AES_CBC_KEY_SIZE_MAX (AES_CBC_KEY_SIZE_256)

/*
 * The size of the AES-CBC initialization vector in bytes.
 */
#define AES_CBC_IV_SIZE (16)

/*
 * The fixed block size used by AES in bytes.
 */
#define AES_CBC_BLOCK_SIZE (16)

/*
 * Opaque AES context operating in CBC mode. Note that there are undefined
 * behaviours, described below, with this opaque structure.
 */
struct aes_cbc_ctx;

/*
 * Allocates a new AES context operating in CBC mode. Must be freed with
 * aes_cbc_free_scrub(). Guaranteed to return non-NULL; it is a fatal error for
 * allocation to fail.
 */
struct aes_cbc_ctx *aes_cbc_alloc(void);

/*
 * Performs the key schedule expansion for either AES encryption or AES
 * decryption, storing the computed round keys and decryption round keys in
 * the context. It is a fatal error if keyBytes is not one of
 * AES_CBC_KEY_SIZE_128, AES_CBC_KEY_SIZE_192, or AES_CBC_KEY_SIZE_256.
 */
void aes_cbc_set_key(struct aes_cbc_ctx *ctx, const byte_t *key,
                     size_t keyBytes);

/*
 * Sets the initialization vector that will be used for the next block
 * operation (encryption or decryption).
 */
void aes_cbc_set_iv(struct aes_cbc_ctx *ctx, const byte_t *iv);

/*
 * Encrypts or decrypts a single block of data using the given context and
 * stores the encrypted or decrypted block in the output. The initialization
 * vector will be updated with a new value, per the CBC algorithm.
 *
 * The two pointers, block and output, cannot overlap.
 *
 * The output of these functions is undefined if either of aes_cbc_set_key() or
 * aes_cbc_set_iv() has not been called.
 */
void aes_cbc_encrypt(struct aes_cbc_ctx *ctx, const byte_t *block,
                     byte_t *output);
void aes_cbc_decrypt(struct aes_cbc_ctx *ctx, const byte_t *block,
                     byte_t *output);

/*
 * Frees an AES context allocated with aes_cbc_alloc(), and securely scrubs all
 * memory allocated for the context. Calling with NULL is a no-op.
 */
void aes_cbc_free_scrub(struct aes_cbc_ctx *ctx);

#endif
