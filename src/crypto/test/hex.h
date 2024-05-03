/*
 * Copyright (c) 2024 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_CRYPTO_TEST_HEX_H_
#define PISCES_CRYPTO_TEST_HEX_H_

#include "common/bytetype.h"

#include <stddef.h>

/*
 * The largest input string size accepted by hex_to_bytes(), and the largest
 * possible number of bytes output by that function.
 */
#define HEX_TO_BYTES_MAX_STRLEN    (1000)
#define HEX_TO_BYTES_MAX_NUM_BYTES (HEX_TO_BYTES_MAX_STRLEN / 2)

/*
 * Converts a string of hexadecimal characters to an array of bytes. The string
 * must contain only the characters 0-9 and A-F (or a-f), with no prefix of
 * "0x".
 *
 * A new array will be allocated and used to store the bytes, in *bytes. The
 * caller will be responsible for freeing it. The size of the allocated array
 * will be stored in *numBytes.
 */
void hex_to_bytes(const char *hex, byte_t **bytes, size_t *numBytes);

#endif
