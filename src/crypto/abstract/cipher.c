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
#include "common/unusedvar.h"
#include "crypto/algorithms/pkcs7/pkcs7_padding.h"
#include "crypto/primitives/aes/aes_cbc.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/*
 * The context only supports AES with different key sizes, because that is the
 * only primitive used in this header.
 */
struct cipher_ctx {
    struct aes_cbc_ctx *ctx;
    size_t keyBytes;
    int algPadded;
    cipher_direction_t direction;
    byte_t iv0[CIPHER_MAX_IV_BYTES];
    byte_t inputBlock[CIPHER_MAX_BLOCK_BYTES];
    size_t amntInput;
    byte_t outputBlock[CIPHER_MAX_BLOCK_BYTES];
    int hasOutput;
    int wasDirectionSet;
    int wasIVSet;
    int wasKeySet;
    int isRunning;
    int errorCode;
};

/*
 * Encrypts or decrypts the given block of data, updating any holdback in the
 * context when using padding with decryption. Returns the amount of data
 * placed into the output buffer.
 */
static size_t process_block(struct cipher_ctx *cipher, const byte_t *block,
                            byte_t *output);

struct cipher_ctx *cipher_alloc(cipher_algorithm_t alg)
{
    struct cipher_ctx *ret = calloc(1, sizeof(struct cipher_ctx));
    ASSERT_ALLOC(ret);

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
        FATAL_ERROR("Invalid cipher algorithm");
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

void cipher_add(struct cipher_ctx *cipher, const byte_t *bytes,
                size_t numBytes, byte_t *output, size_t *outputBytes)
{
    size_t toFillBlock, addToCipher;
    size_t fakeOutputBytes, addedToOutput;

    ASSERT(cipher->isRunning, "Cannot add data to non-running cipher");
    ASSERT(numBytes <= CIPHER_ADD_MAX_INPUT_SIZE,
           "Cipher maximum single-input data size exceeded");

    if (outputBytes == NULL) {
        outputBytes = &fakeOutputBytes;
    }
    *outputBytes = 0;

    /* Process the input block-by-block */
    while (numBytes > 0) {
        if (cipher->amntInput == 0 && numBytes >= AES_CBC_BLOCK_SIZE) {
            addedToOutput = process_block(cipher, bytes, output);
            bytes += AES_CBC_BLOCK_SIZE;
            numBytes -= AES_CBC_BLOCK_SIZE;
        }
        else {
            toFillBlock = AES_CBC_BLOCK_SIZE - cipher->amntInput;
            addToCipher = (toFillBlock < numBytes ? toFillBlock : numBytes);
            memcpy(cipher->inputBlock + cipher->amntInput, bytes, addToCipher);

            /*
             * cipher->amntInput is bounded by the block size, so there is no
             * risk of overflow.
             */
            cipher->amntInput += addToCipher;
            bytes += addToCipher;
            numBytes -= addToCipher;
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
         * of CIPHER_ADD_MAX_INPUT_SIZE on numBytes. Specifically, outputBytes
         * will never exceed numBytes+b-1, where b is the block size of the
         * cipher, because at least one byte would be required to fill any
         * partial block already in this context's buffer, and beyond that only
         * full blocks are processed.
         */
        output += addedToOutput;
        *outputBytes += addedToOutput;
        ASSERT(*outputBytes >= addedToOutput,
               "Integer overflow in cipher input processing");
    }
}

int cipher_end(struct cipher_ctx *cipher, byte_t *output, size_t *outputBytes)
{
    size_t fakeOutputBytes;
    int errVal = 0;

    ASSERT(cipher->isRunning, "Cannot end operation on non-running cipher");
    cipher->isRunning = 0;

    /* If an error has occurred, return 0 result bytes */
    if (outputBytes == NULL) {
        outputBytes = &fakeOutputBytes;
    }
    *outputBytes = 0;

    /*
     * Encrypt or decrypt a final block if necessary.
     */
    if (cipher->algPadded && cipher->direction == CIPHER_DIRECTION_ENCRYPT) {
        /*
         * Encrypting with padding is just: pad whatever (if anything) is in
         * the input buffer and encrypt it.
         */
        pkcs7_padding_add(cipher->inputBlock, cipher->amntInput,
                          AES_CBC_BLOCK_SIZE, cipher->inputBlock);
        aes_cbc_encrypt(cipher->ctx, cipher->inputBlock, output);
        *outputBytes = AES_CBC_BLOCK_SIZE;
    }
    else if (cipher->algPadded &&
             cipher->direction == CIPHER_DIRECTION_DECRYPT) {
        /*
         * Decryption with padding requires a complete decrypted block in the
         * output buffer, but nothing left to process in the input buffer.
         */
        if (cipher->hasOutput == 0) {
            ERROR_CODE(isErr, errVal, CIPHER_ERROR_NO_BLOCK_TO_DEPAD);
        }
        else if (cipher->amntInput != 0) {
            ERROR_CODE(isErr, errVal,
                       CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE);
        }
        if (pkcs7_padding_remove(cipher->outputBlock, AES_CBC_BLOCK_SIZE,
                                 output, outputBytes)) {
            ERROR_CODE(isErr, errVal, CIPHER_ERROR_INVALID_PAD_DATA);
        }
    }
    else if (cipher->amntInput != 0) {
        /*
         * No padding, but input left in the input buffer, is an error. Note:
         * the output buffer is only used if there is padding, so in this case
         * the output buffer is guaranteed to be empty.
         */
        ERROR_CODE(isErr, errVal, CIPHER_ERROR_INPUT_SIZE_NOT_BLOCK_MULTIPLE);
    }

isErr:
    if (errVal) {
        *outputBytes = 0;
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
        FATAL_ERROR("Invalid cipher error code");
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

static size_t process_block(struct cipher_ctx *cipher, const byte_t *block,
                            byte_t *output)
{
    size_t ret;

    if (cipher->direction == CIPHER_DIRECTION_ENCRYPT) {
        aes_cbc_encrypt(cipher->ctx, block, output);
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
        aes_cbc_decrypt(cipher->ctx, block, cipher->outputBlock);
    }
    else {
        aes_cbc_decrypt(cipher->ctx, block, output);
        ret = AES_CBC_BLOCK_SIZE;
    }

    return ret;
}
