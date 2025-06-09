/*
 * Copyright (c) 2023-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_CRYPTO_ALGORITHMS_PKCS7_PKCS7_PADDING_H_
#define PISCES_CRYPTO_ALGORITHMS_PKCS7_PKCS7_PADDING_H_

#include "common/bytetype.h"

#include <stddef.h>

#define PKCS7_PADDING_ERROR_INVALID_PAD_DATA (-1)

/*
 * PKCS7 padding is defined in RFC 5652 section 6.3. It requires a positive
 * block size no greater than 255 bytes.
 */

/*
 * Adds PKCS7 padding to an incomplete final block of data. The input block
 * must contain between 0 and block_size-1 bytes of data, inclusive. The output
 * will be exactly block_size bytes. The two buffers may overlap.
 */
void pkcs7_padding_add(const byte *unpadded, size_t unpadded_len,
                       size_t block_size, byte *padded);

/*
 * Removes PKCS7 padding from a final block of data. The input block must be
 * exactly block_size bytes long. The output will be between 0 and block_size-1
 * bytes, inclusive. The two buffers may overlap. Returns 0 on success, <0 on
 * error (PKCS7_PADDING_ERROR_INVALID_PAD_DATA).
 */
int pkcs7_padding_remove(const byte *padded, size_t block_size, byte *unpadded,
                         size_t *unpadded_len);

#endif
