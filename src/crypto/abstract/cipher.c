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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * This abstract context contains a struct aes_cbc_ctx *, instead of a void *,
 * because AES-CBC is the only primitive supported in this implementation.
 */
struct cipher_ctx {
    struct aes_cbc_ctx *ctx;
    size_t keyBytes;
    int algPadded;
    cipher_direction_t direction;
    byte_t iv0[CIPHER_MAX_IV_SIZE];
    byte_t inputBlock[CIPHER_MAX_BLOCK_SIZE];
    size_t amntInput;
    byte_t outputBlock[CIPHER_MAX_BLOCK_SIZE];
    int hasOutput;
    int wasDirectionSet;
    int wasIVSet;
    int wasKeySet;
    int isRunning;
    int errorCode;
};

static size_t process_block(struct cipher_ctx *cipher, const byte_t *input,
                            byte_t *output);

#define UNUSED(varname) (void)(varname)

struct cipher_ctx *cipher_alloc(cipher_algorithm_t alg)
{
    struct cipher_ctx *ret = calloc(1, sizeof(struct cipher_ctx));
    GUARD_ALLOC(ret);

    switch (alg) {
    case CIPHER_ALG_AES_128_CBC_NOPAD:
        ret->keyBytes = AES_CBC_KEY_SIZE_128;
        break;
    case CIPHER_ALG_AES_128_CBC_PKCS7PAD:
        ret->keyBytes = AES_CBC_KEY_SIZE_128;
        ret->algPadded = 1;
        break;
    case CIPHER_ALG_AES_256_CBC_NOPAD:
        ret->keyBytes = AES_CBC_KEY_SIZE_256;
        break;
    case CIPHER_ALG_AES_256_CBC_PKCS7PAD:
        ret->keyBytes = AES_CBC_KEY_SIZE_256;
        ret->algPadded = 1;
        break;
    default:
        ASSERT_NEVER_REACH("Invalid cipher algorithm");
    }

    ret->ctx = aes_cbc_alloc();
    return ret;
}

void cipher_set_direction(struct cipher_ctx *cipher,
                          cipher_direction_t direction)
{
    ASSERT(cipher->isRunning == 0, "Cannot set direction on running cipher");
    ASSERT(direction == CIPHER_DIRECTION_ENCRYPT ||
               direction == CIPHER_DIRECTION_DECRYPT,
           "Invalid cipher direction");
    cipher->direction = direction;
    cipher->wasDirectionSet = 1;
}

void cipher_set_key(struct cipher_ctx *cipher, const byte_t *key)
{
    ASSERT(cipher->isRunning == 0, "Cannot set key on running cipher");
    aes_cbc_set_key(cipher->ctx, key, cipher->keyBytes);
    cipher->wasKeySet = 1;
}

void cipher_set_iv(struct cipher_ctx *cipher, const byte_t *iv)
{
    ASSERT(cipher->isRunning == 0, "Cannot set IV on running cipher");
    memcpy(cipher->iv0, iv, AES_CBC_IV_SIZE);
    cipher->wasIVSet = 1;
}

void cipher_start(struct cipher_ctx *cipher)
{
    ASSERT(cipher->wasDirectionSet, "Cannot start cipher without direction");
    ASSERT(cipher->wasIVSet, "Cannot start cipher without IV");
    ASSERT(cipher->wasKeySet, "Cannot start cipher without key");

    cipher->isRunning = 1;
    cipher->errorCode = 0;
    aes_cbc_set_iv(cipher->ctx, cipher->iv0);
}

void cipher_add(struct cipher_ctx *cipher, const byte_t *input,
                size_t inputLen, byte_t *output, size_t *outputLen)
{
    size_t toFillBlock, addToCipher;
    size_t fakeOutputLen, addedToOutput;

    ASSERT(cipher->isRunning, "Cannot add data to non-running cipher");
    ASSERT(inputLen <= CIPHER_ADD_MAX_INPUT_LEN,
           "Cipher maximum single-input data length exceeded");

    if (outputLen == NULL) {
        outputLen = &fakeOutputLen;
    }
    *outputLen = 0;

    /* Process the input block-by-block */
    while (inputLen > 0) {
        if (cipher->amntInput == 0 && inputLen >= AES_CBC_BLOCK_SIZE) {
            addedToOutput = process_block(cipher, input, output);
            input += AES_CBC_BLOCK_SIZE;
            inputLen -= AES_CBC_BLOCK_SIZE;
        }
        else {
            toFillBlock = AES_CBC_BLOCK_SIZE - cipher->amntInput;
            addToCipher = (toFillBlock < inputLen ? toFillBlock : inputLen);
            memcpy(cipher->inputBlock + cipher->amntInput, input, addToCipher);

            /*
             * cipher->amntInput is bounded by the block size, so there is no
             * risk of overflow.
             */
            cipher->amntInput += addToCipher;
            input += addToCipher;
            inputLen -= addToCipher;
            if (cipher->amntInput == AES_CBC_BLOCK_SIZE) {
                cipher->amntInput = 0;
                addedToOutput =
                    process_block(cipher, cipher->inputBlock, output);
            }
            else {
                addedToOutput = 0;
            }
        }

        /*
         * The integer overflow should never trigger, given the bound
         * of CIPHER_ADD_MAX_INPUT_LEN on inputLen. Specifically, outputLen
         * will never exceed inputLen+b-1, where b is the block size of the
         * cipher, because at least one byte would be required to fill any
         * partial block already in this context's buffer, and beyond that only
         * full blocks are processed.
         */
        output += addedToOutput;
        *outputLen += addedToOutput;
        ASSERT(*outputLen >= addedToOutput,
               "Integer overflow in cipher input processing");
    }
}

int cipher_end(struct cipher_ctx *cipher, byte_t *output, size_t *outputLen)
{
    size_t fakeOutputLen;
    int errVal = 0;

    ASSERT(cipher->isRunning, "Cannot end operation on non-running cipher");
    cipher->isRunning = 0;

    if (outputLen == NULL) {
        outputLen = &fakeOutputLen;
    }
    *outputLen = 0;

    /* Encrypt or decrypt a final block if necessary */
    if (cipher->algPadded && cipher->direction == CIPHER_DIRECTION_ENCRYPT) {
        /*
         * Encrypting with padding is just: pad whatever (if anything) is in
         * the input buffer and encrypt it.
         */
        pkcs7_padding_add(cipher->inputBlock, cipher->amntInput,
                          AES_CBC_BLOCK_SIZE, cipher->inputBlock);
        aes_cbc_encrypt(cipher->ctx, cipher->inputBlock, output);
        *outputLen = AES_CBC_BLOCK_SIZE;
    }
    else if (cipher->algPadded &&
             cipher->direction == CIPHER_DIRECTION_DECRYPT) {
        /*
         * Decryption with padding requires a complete decrypted block in the
         * output buffer, but nothing left to process in the input buffer.
         */
        if (cipher->amntInput != 0) {
            ERROR_CODE(isErr, errVal,
                       CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE);
        }
        else if (cipher->hasOutput == 0) {
            ERROR_CODE(isErr, errVal, CIPHER_ERROR_NO_BLOCK_TO_DEPAD);
        }
        if (pkcs7_padding_remove(cipher->outputBlock, AES_CBC_BLOCK_SIZE,
                                 output, outputLen)) {
            ERROR_CODE(isErr, errVal, CIPHER_ERROR_INVALID_PAD_DATA);
        }
    }
    else if (cipher->amntInput != 0) {
        /*
         * No padding is being used. Because the output buffer is only used
         * when there is padding, it is guaranteed to be empty. But, we cannot
         * process any data (a partial block) that might be left in the input
         * buffer.
         */
        ERROR_CODE(isErr, errVal, CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE);
    }

isErr:
    if (errVal) {
        *outputLen = 0;
    }
    cipher->errorCode = errVal;
    return errVal;
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
    return cipher->keyBytes;
}

const char *cipher_error(const struct cipher_ctx *cipher)
{
    switch (cipher->errorCode) {
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

static size_t process_block(struct cipher_ctx *cipher, const byte_t *input,
                            byte_t *output)
{
    size_t ret;

    if (cipher->direction == CIPHER_DIRECTION_ENCRYPT) {
        aes_cbc_encrypt(cipher->ctx, input, output);
        ret = AES_CBC_BLOCK_SIZE;
    }
    else if (cipher->algPadded) {
        if (cipher->hasOutput) {
            memcpy(output, cipher->outputBlock, AES_CBC_BLOCK_SIZE);
            ret = AES_CBC_BLOCK_SIZE;
        }
        else {
            cipher->hasOutput = 1;
            ret = 0;
        }
        aes_cbc_decrypt(cipher->ctx, input, cipher->outputBlock);
    }
    else {
        aes_cbc_decrypt(cipher->ctx, input, output);
        ret = AES_CBC_BLOCK_SIZE;
    }

    return ret;
}
