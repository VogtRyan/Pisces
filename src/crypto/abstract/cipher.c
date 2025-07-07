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

#include "cipher.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/algorithms/pkcs7/pkcs7_padding.h"
#include "crypto/primitives/aes/aes_cbc.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#define UNUSED(varname) (void)(varname)

/*
 * This abstract context contains a struct aes_cbc_ctx *, instead of a void *,
 * because AES-CBC is the only primitive supported. The key_size field is used
 * as a proxy for an abstract type field.
 */
struct cipher_ctx {
    struct aes_cbc_ctx *ctx;
    byte input_block[CIPHER_MAX_BLOCK_SIZE];
    byte iv0[CIPHER_MAX_IV_SIZE];
    byte output_block[CIPHER_MAX_BLOCK_SIZE];
    size_t amnt_input;
    size_t key_size;
    cipher_direction direction;
    int errcode;
    bool direction_set;
    bool has_output;
    bool iv_set;
    bool key_set;
    bool padded;
    bool running;
};

static size_t process_block(struct cipher_ctx *cipher, const byte *input,
                            byte *output);

struct cipher_ctx *cipher_alloc(cipher_algorithm alg)
{
    struct cipher_ctx *ret;

    ret = calloc(1, sizeof(struct cipher_ctx));
    GUARD_ALLOC(ret);

    switch (alg) {
    case CIPHER_ALG_AES_128_CBC_NOPAD:
        ret->key_size = AES_CBC_KEY_SIZE_128;
        break;
    case CIPHER_ALG_AES_128_CBC_PKCS7PAD:
        ret->key_size = AES_CBC_KEY_SIZE_128;
        ret->padded = true;
        break;
    case CIPHER_ALG_AES_256_CBC_NOPAD:
        ret->key_size = AES_CBC_KEY_SIZE_256;
        break;
    case CIPHER_ALG_AES_256_CBC_PKCS7PAD:
        ret->key_size = AES_CBC_KEY_SIZE_256;
        ret->padded = true;
        break;
    default:
        ASSERT_NEVER_REACH("Invalid cipher algorithm");
    }

    ret->ctx = aes_cbc_alloc();
    return ret;
}

void cipher_set_direction(struct cipher_ctx *cipher,
                          cipher_direction direction)
{
    ASSERT(cipher->running == false, "Cannot set direction on running cipher");
    ASSERT(direction == CIPHER_DIRECTION_ENCRYPT ||
               direction == CIPHER_DIRECTION_DECRYPT,
           "Invalid cipher direction");

    cipher->direction = direction;
    cipher->direction_set = true;
}

void cipher_set_key(struct cipher_ctx *cipher, const byte *key)
{
    ASSERT(cipher->running == false, "Cannot set key on running cipher");

    aes_cbc_set_key(cipher->ctx, key, cipher->key_size);
    cipher->key_set = true;
}

void cipher_set_iv(struct cipher_ctx *cipher, const byte *iv)
{
    ASSERT(cipher->running == false, "Cannot set IV on running cipher");

    memcpy(cipher->iv0, iv, AES_CBC_IV_SIZE);
    cipher->iv_set = true;
}

void cipher_start(struct cipher_ctx *cipher)
{
    ASSERT(cipher->direction_set, "Cannot start cipher without direction");
    ASSERT(cipher->iv_set, "Cannot start cipher without IV");
    ASSERT(cipher->key_set, "Cannot start cipher without key");

    cipher->running = true;
    cipher->errcode = 0;
    aes_cbc_set_iv(cipher->ctx, cipher->iv0);
}

void cipher_add(struct cipher_ctx *cipher, const byte *input, size_t input_len,
                byte *output, size_t *output_len)
{
    size_t add_to_cipher, added_to_output, to_fill_block;
    size_t fake_output_len;

    ASSERT(cipher->running, "Cannot add data to non-running cipher");
    ASSERT(input_len <= CIPHER_ADD_MAX_INPUT_LEN,
           "Cipher maximum single-input data length exceeded");

    if (output_len == NULL) {
        output_len = &fake_output_len;
    }
    *output_len = 0;

    /* Process the input block-by-block */
    while (input_len > 0) {
        if (cipher->amnt_input == 0 && input_len >= AES_CBC_BLOCK_SIZE) {
            added_to_output = process_block(cipher, input, output);
            input += AES_CBC_BLOCK_SIZE;
            input_len -= AES_CBC_BLOCK_SIZE;
        }
        else {
            to_fill_block = AES_CBC_BLOCK_SIZE - cipher->amnt_input;
            add_to_cipher = MIN(to_fill_block, input_len);
            memcpy(cipher->input_block + cipher->amnt_input, input,
                   add_to_cipher);

            /*
             * cipher->amnt_input is bounded by the block size, so there is no
             * risk of overflow.
             */
            cipher->amnt_input += add_to_cipher;
            input += add_to_cipher;
            input_len -= add_to_cipher;
            if (cipher->amnt_input == AES_CBC_BLOCK_SIZE) {
                cipher->amnt_input = 0;
                added_to_output =
                    process_block(cipher, cipher->input_block, output);
            }
            else {
                added_to_output = 0;
            }
        }

        /*
         * The integer overflow should never trigger, given the bound
         * of CIPHER_ADD_MAX_INPUT_LEN on input_len. Specifically, output_len
         * will never exceed input_len+b-1, where b is the block size of the
         * cipher, because at least one byte would be required to fill any
         * partial block already in this context's buffer, and beyond that only
         * full blocks are processed.
         */
        output += added_to_output;
        *output_len += added_to_output;
        ASSERT(*output_len >= added_to_output,
               "Integer overflow in cipher input processing");
    }
}

int cipher_end(struct cipher_ctx *cipher, byte *output, size_t *output_len)
{
    size_t fake_output_len;
    int errval = 0;

    ASSERT(cipher->running, "Cannot end operation on non-running cipher");
    cipher->running = false;

    if (output_len == NULL) {
        output_len = &fake_output_len;
    }

    /* Encrypt or decrypt a final block if necessary */
    if (cipher->padded && cipher->direction == CIPHER_DIRECTION_ENCRYPT) {
        /*
         * Encrypting with padding is just: pad whatever (if anything) is in
         * the input buffer and encrypt it.
         */
        pkcs7_padding_add(cipher->input_block, cipher->amnt_input,
                          AES_CBC_BLOCK_SIZE, cipher->input_block);
        aes_cbc_encrypt(cipher->ctx, cipher->input_block, output);
        *output_len = AES_CBC_BLOCK_SIZE;
    }
    else if (cipher->padded && cipher->direction == CIPHER_DIRECTION_DECRYPT) {
        /*
         * Decryption with padding requires a complete decrypted block in the
         * output buffer, but nothing left to process in the input buffer.
         */
        if (cipher->amnt_input != 0) {
            ERROR_GOTO_SILENT_VAL(done, errval,
                                  CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE);
        }
        else if (cipher->has_output == false) {
            ERROR_GOTO_SILENT_VAL(done, errval,
                                  CIPHER_ERROR_NO_BLOCK_TO_DEPAD);
        }
        if (pkcs7_padding_remove(cipher->output_block, AES_CBC_BLOCK_SIZE,
                                 output, output_len)) {
            ERROR_GOTO_SILENT_VAL(done, errval, CIPHER_ERROR_INVALID_PAD_DATA);
        }
    }
    else if (cipher->amnt_input != 0) {
        /*
         * No padding is being used. Because the output buffer is only used
         * when there is padding, it is guaranteed to be empty. But, we cannot
         * process any data (a partial block) that might be left in the input
         * buffer.
         */
        ERROR_GOTO_SILENT_VAL(done, errval,
                              CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE);
    }

done:
    if (errval) {
        *output_len = 0;
    }
    cipher->errcode = errval;
    return errval;
}

size_t cipher_block_size(const struct cipher_ctx *cipher)
{
    UNUSED(cipher);
    return AES_CBC_BLOCK_SIZE;
}

size_t cipher_iv_size(const struct cipher_ctx *cipher)
{
    UNUSED(cipher);
    return AES_CBC_IV_SIZE;
}

size_t cipher_key_size(const struct cipher_ctx *cipher)
{
    return cipher->key_size;
}

const char *cipher_error(const struct cipher_ctx *cipher)
{
    switch (cipher->errcode) {
    case 0:
        return "No error in cipher context";
    case CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE:
        return "Cipher input size not a multiple of block size";
    case CIPHER_ERROR_INVALID_PAD_DATA:
        return "Cipher padding data is invalid";
    case CIPHER_ERROR_NO_BLOCK_TO_DEPAD:
        return "Cipher lacks input block to de-pad";
    default:
        ASSERT_NEVER_REACH("Invalid cipher error code");
    }
}

void cipher_free_scrub(struct cipher_ctx *cipher)
{
    if (cipher != NULL) {
        aes_cbc_free_scrub(cipher->ctx);
        scrub_memory(cipher, sizeof(struct cipher_ctx));
        free(cipher);
    }
}

static size_t process_block(struct cipher_ctx *cipher, const byte *input,
                            byte *output)
{
    size_t ret;

    if (cipher->direction == CIPHER_DIRECTION_ENCRYPT) {
        aes_cbc_encrypt(cipher->ctx, input, output);
        ret = AES_CBC_BLOCK_SIZE;
    }
    else if (cipher->padded) {
        if (cipher->has_output) {
            memcpy(output, cipher->output_block, AES_CBC_BLOCK_SIZE);
            ret = AES_CBC_BLOCK_SIZE;
        }
        else {
            cipher->has_output = true;
            ret = 0;
        }
        aes_cbc_decrypt(cipher->ctx, input, cipher->output_block);
    }
    else {
        aes_cbc_decrypt(cipher->ctx, input, output);
        ret = AES_CBC_BLOCK_SIZE;
    }

    return ret;
}
