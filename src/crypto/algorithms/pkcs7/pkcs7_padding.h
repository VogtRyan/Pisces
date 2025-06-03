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

/*
 * The error code returned by pkcs7_padding_remove() if the provided input
 * block does not conform to the format of a PKCS7-padded block.
 */
#define PKCS7_PADDING_ERROR_INVALID_PAD_DATA (-1)

/*
 * Add PKCS7 padding, as defined in RFC 5652 section 6.3, to a final block of
 * data. The final block input size must contain between 0 and blockSize-1
 * bytes of data, and blockSize must be a positive value less than or equal to
 * 255.
 *
 * The size of the output will be exactly blockSize bytes. The input and output
 * buffers may overlap.
 *
 * It is a fatal error for the block size or input size to be out of range.
 */
void pkcs7_padding_add(const byte *input, size_t inputSize, size_t blockSize,
                       byte *output);

/*
 * Remove the PKCS7 padding, as defined in RFC 5652 section 6.3, from a final
 * block of data. The final block of data must be exactly blockSize bytes long,
 * and blockSize must be a positive value less than or equal to 255.
 *
 * The block with the padding removed will be written to the output buffer, and
 * the size of the data with its padding removed will be stored in *outputSize.
 * The input and output buffers may overlap.
 *
 * On success, the function returns 0. If the input does not conform to the
 * padding scheme then a negative value, specifically
 * PKCS7_PADDING_ERROR_INVALID_PAD_DATA, will be returned and the output buffer
 * and value of *outputSize will remain unchanged.
 *
 * It is a fatal error for the block size to be out of range.
 */
int pkcs7_padding_remove(const byte *input, size_t blockSize, byte *output,
                         size_t *outputSize);

#endif
