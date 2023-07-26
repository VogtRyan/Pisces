/*
 * Copyright (c) 2011-2023 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_CRYPTO_PRIMITIVES_AES_AES_ECB_H_
#define PISCES_CRYPTO_PRIMITIVES_AES_AES_ECB_H_

#include "common/bytetype.h"

#include <stddef.h>

/*
 * Possible key sizes, equal to the number of bytes in the key.
 */
#define AES_ECB_KEY_SIZE_128 (16)
#define AES_ECB_KEY_SIZE_192 (24)
#define AES_ECB_KEY_SIZE_256 (32)

/*
 * The fixed block size used by AES in bytes.
 */
#define AES_ECB_BLOCK_SIZE (16)

/*
 * Opaque AES context operating in ECB mode. Note that there are undefined
 * behaviours, described below, with this opaque structure.
 */
struct aes_ecb_ctx;

/*
 * Allocates a new AES context operating in ECB mode. Must be freed with
 * aes_ecb_free_scrub(). Guaranteed to return non-NULL; it is a fatal error for
 * allocation to fail.
 */
struct aes_ecb_ctx *aes_ecb_alloc(void);

/*
 * Performs the key schedule expansion for both AES encryption and AES
 * decryption, storing the computed round keys and decryption round keys in
 * the context. It is a fatal error if keyBytes is not one of
 * AES_ECB_KEY_SIZE_128, AES_ECB_KEY_SIZE_192, or AES_ECB_KEY_SIZE_256.
 */
void aes_ecb_set_key(struct aes_ecb_ctx *ctx, const byte_t *key,
                     size_t keyBytes);

/*
 * Encrypts or decrypts a single block of data using the given context and
 * stores the encrypted or decrypted block in the output. The two pointers,
 * block and output, may overlap. The output of these functions is undefined
 * if aes_ecb_set_key() has not been called.
 */
void aes_ecb_encrypt(struct aes_ecb_ctx *ctx, const byte_t *block,
                     byte_t *output);
void aes_ecb_decrypt(struct aes_ecb_ctx *ctx, const byte_t *block,
                     byte_t *output);

/*
 * Frees an AES context allocated with aes_ecb_alloc(), and securely scrubs all
 * memory allocated for the context. Calling with NULL is a no-op.
 */
void aes_ecb_free_scrub(struct aes_ecb_ctx *ctx);

#endif
