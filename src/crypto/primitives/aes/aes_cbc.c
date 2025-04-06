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

#include "aes_cbc.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/primitives/aes/aes_ecb.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct aes_cbc_ctx {
    struct aes_ecb_ctx *ecbCtx;
    byte_t iv[AES_CBC_IV_SIZE];
};

struct aes_cbc_ctx *aes_cbc_alloc(void)
{
    struct aes_cbc_ctx *ret =
        (struct aes_cbc_ctx *)calloc(1, sizeof(struct aes_cbc_ctx));
    GUARD_ALLOC(ret);
    ret->ecbCtx = aes_ecb_alloc();
    return ret;
}

void aes_cbc_set_key(struct aes_cbc_ctx *ctx, const byte_t *key,
                     size_t keyBytes)
{
    switch (keyBytes) {
    case AES_CBC_KEY_SIZE_128:
        aes_ecb_set_key(ctx->ecbCtx, key, AES_ECB_KEY_SIZE_128);
        break;
    case AES_CBC_KEY_SIZE_192:
        aes_ecb_set_key(ctx->ecbCtx, key, AES_ECB_KEY_SIZE_192);
        break;
    case AES_CBC_KEY_SIZE_256:
        aes_ecb_set_key(ctx->ecbCtx, key, AES_ECB_KEY_SIZE_256);
        break;
    default:
        ASSERT_NEVER_REACH("Invalid AES-CBC key size");
    }
}

void aes_cbc_set_iv(struct aes_cbc_ctx *ctx, const byte_t *iv)
{
    memcpy(ctx->iv, iv, AES_CBC_IV_SIZE);
}

void aes_cbc_encrypt(struct aes_cbc_ctx *ctx, const byte_t *block,
                     byte_t *output)
{
    /*
     * Ciphertext = E(plaintext ^ IV)
     * Next IV = ciphertext
     *
     * In CBC mode, the IV size is equal to the block size.
     */
    size_t i;
    for (i = 0; i < AES_CBC_BLOCK_SIZE; i++) {
        ctx->iv[i] ^= block[i];
    }
    aes_ecb_encrypt(ctx->ecbCtx, ctx->iv, output);
    memcpy(ctx->iv, output, AES_CBC_BLOCK_SIZE);
}

void aes_cbc_decrypt(struct aes_cbc_ctx *ctx, const byte_t *block,
                     byte_t *output)
{
    /*
     * Plaintext = D(ciphertext) ^ IV
     * Next IV = ciphertext
     *
     * In CBC mode, the IV size is equal to the block size.
     */
    size_t i;
    aes_ecb_decrypt(ctx->ecbCtx, block, output);
    for (i = 0; i < AES_CBC_BLOCK_SIZE; i++) {
        output[i] ^= ctx->iv[i];
    }
    memcpy(ctx->iv, block, AES_CBC_BLOCK_SIZE);
}

void aes_cbc_free_scrub(struct aes_cbc_ctx *ctx)
{
    if (ctx != NULL) {
        aes_ecb_free_scrub(ctx->ecbCtx);
        scrub_memory(ctx, sizeof(struct aes_cbc_ctx));
        free(ctx);
    }
}
