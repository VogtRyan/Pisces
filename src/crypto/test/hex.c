/*
 * Copyright (c) 2024-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "hex.h"

#include "common/bytetype.h"
#include "common/errorflow.h"

#include <stddef.h>
#include <string.h>

/*
 * Returns the number of bytes represented by the given hexadecimal string. It
 * is a fatal error for the length of the hex string to be greater than
 * HEX_TO_BYTES_MAX_STRLEN or to be odd.
 */
static size_t hex_byte_len(const char *hex);

void hex_to_bytes(const char *hex, byte_t **bytes, size_t *numBytes)
{
    size_t outLen;
    byte_t *out;
    unsigned int byteVal;
    int scanRes;

    outLen = hex_byte_len(hex);
    out = (byte_t *)calloc(outLen, 1);
    GUARD_ALLOC(out);

    *numBytes = outLen;
    *bytes = out;

    while (outLen > 0) {
        scanRes = sscanf(hex, "%2x", &byteVal);
        ASSERT(scanRes == 1, "Invalid value in hexadecimal string");
        *out++ = (byte_t)byteVal;
        hex += 2;
        outLen--;
    }
}

static size_t hex_byte_len(const char *hex)
{
    size_t inLen = 0;

    /*
     * Essentially a portable substitute for strnlen(), for POSIX.1-2001
     * compatibility.
     */
    while (inLen < HEX_TO_BYTES_MAX_STRLEN) {
        if (hex[inLen] == '\0') {
            break;
        }
        inLen++;
    }

    ASSERT(hex[inLen] == '\0', "Input hexadecimal string too long");
    ASSERT(inLen % 2 == 0, "Input hexadecimal string has odd length: %zu",
           inLen);

    return inLen / 2;
}
