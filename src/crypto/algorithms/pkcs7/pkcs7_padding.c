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

#include "pkcs7_padding.h"

#include "common/bytetype.h"
#include "common/errorflow.h"

#include <stddef.h>
#include <string.h>

void pkcs7_padding_add(const byte *unpadded, size_t unpadded_len,
                       size_t block_size, byte *padded)
{
    size_t pad_value, i;

    /* Block size has to be expressible in a single unsigned byte */
    ASSERT(block_size > 0 && block_size <= 255,
           "PKCS7 padding incompatible with given block size");

    /* The final block has to be incomplete, even if it is empty */
    ASSERT(unpadded_len < block_size,
           "Input for PKCS7 padding is not an incomplete block");

    /*
     * Every byte after the last byte of unpadded data is set to the number of
     * bytes of padding.
     */
    memmove(padded, unpadded, unpadded_len);
    pad_value = block_size - unpadded_len;
    for (i = unpadded_len; i < block_size; i++) {
        padded[i] = (byte)pad_value;
    }
}

int pkcs7_padding_remove(const byte *padded, size_t block_size, byte *unpadded,
                         size_t *unpadded_len)
{
    size_t pad_value, i;

    /* Block size has to be expressible in a single unsigned byte */
    ASSERT(block_size > 0 && block_size <= 255,
           "PKCS7 padding incompatible with given block size");

    /*
     * The amount of padding is the value of the last byte in the padded block.
     * Because there must be some padding in a padded block, the pad value has
     * to be positive, but there cannot be more padding than the size of the
     * block.
     */
    pad_value = (size_t)padded[block_size - 1];
    if (pad_value == 0 || pad_value > block_size) {
        return PKCS7_PADDING_ERROR_INVALID_PAD_DATA;
    }

    /*
     * Every byte of padding must have the same value: the size of the padding.
     * If any byte in the pad differs, the padding is malformed.
     */
    for (i = block_size - pad_value; i < block_size - 1; i++) {
        if (padded[i] != (byte)pad_value) {
            return PKCS7_PADDING_ERROR_INVALID_PAD_DATA;
        }
    }

    /* The pad is intact and can be removed */
    *unpadded_len = block_size - pad_value;
    memmove(unpadded, padded, *unpadded_len);
    return 0;
}
