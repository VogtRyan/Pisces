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

#include "pkcs7_padding.h"

#include "common/bytetype.h"
#include "common/errorflow.h"

#include <stddef.h>
#include <string.h>

void pkcs7_padding_add(const byte_t *input, size_t inputSize, size_t blockSize,
                       byte_t *output)
{
    size_t padValue, i;

    /*
     * For a cipher to be compatible with PKCS7 padding, its block size must be
     * expressible in a single unsigned byte.
     */
    ASSERT(blockSize > 0 && blockSize <= 255,
           "PKCS7 padding incompatible with given block size");

    /*
     * Where PKCS7 padding is used, the final block must have space to insert
     * the padding. The final block could be empty (resulting in a block of
     * nothing but padding), but it cannot be full.
     */
    ASSERT(inputSize < blockSize,
           "Input size for PKCS7 padding not less than block size");

    /*
     * Every byte after the last byte of input data is set to the number of
     * bytes of padding.
     */
    memmove(output, input, inputSize);
    padValue = blockSize - inputSize;
    for (i = inputSize; i < blockSize; i++) {
        output[i] = (byte_t)padValue;
    }
}

int pkcs7_padding_remove(const byte_t *input, size_t blockSize, byte_t *output,
                         size_t *outputSize)
{
    size_t padValue, i;

    /*
     * The block size must be expressible in a single unsigned byte.
     */
    ASSERT(blockSize > 0 && blockSize <= 255,
           "PKCS7 padding incompatible with given block size");

    /*
     * The amount of padding is the value of the last byte in the padded block.
     * Because there must be some padding in a padded block, the pad value has
     * to be positive, but there cannot be more padding than the size of the
     * block.
     */
    padValue = (size_t)input[blockSize - 1];
    if (padValue == 0 || padValue > blockSize) {
        return PKCS7_PADDING_ERROR_INVALID_PAD_DATA;
    }

    /*
     * Every byte of padding must have the same value: the size of the padding.
     * If any byte in the pad differs, the padding is malformed.
     */
    for (i = blockSize - padValue; i < blockSize - 1; i++) {
        if (input[i] != (byte_t)padValue) {
            return PKCS7_PADDING_ERROR_INVALID_PAD_DATA;
        }
    }

    /* The pad is intact and can be removed */
    *outputSize = blockSize - padValue;
    memmove(output, input, *outputSize);
    return 0;
}
