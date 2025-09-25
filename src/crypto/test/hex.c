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

static byte hex_to_byte(const char *hex);

void hex_to_bytearr(struct bytearr *ba, const char *hex)
{
    ba->len = 0;

    while (*hex != '\0') {
        ASSERT(ba->len < BYTEARR_MAX_LEN, "Hex string too long");
        ba->bytes[ba->len] = hex_to_byte(hex);
        ba->len++;
        hex += 2;
    }

    memset(ba->bytes + ba->len, 0, BYTEARR_MAX_LEN - ba->len);
}

static byte hex_to_byte(const char *hex)
{
    int i;
    char c;
    byte ret;

    ret = 0;
    for (i = 0; i < 2; i++) {
        c = hex[0];
        ret <<= 4U;

        ASSERT(c != '\0', "Hex string terminated prematurely");
        ASSERT((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
                   (c >= 'a' && c <= 'f'),
               "Invalid hex character (%c)", c);

        if (c >= '0' && c <= '9') {
            ret |= (byte)(c - '0');
        }
        else if (c >= 'A' && c <= 'F') {
            ret |= (byte)(10U + (c - 'A'));
        }
        else {
            ret |= (byte)(10U + (c - 'a'));
        }

        hex++;
    }

    return ret;
}

/*
 * FIXME: Deprecated
 */

static size_t hex_byte_len(const char *hex);

void hex_to_bytes(const char *hex, byte **bytes, size_t *num_bytes)
{
    size_t out_len;
    byte *out;
    unsigned int byte_val;
    int scan_res;

    out_len = hex_byte_len(hex);
    if (out_len == 0) {
        *bytes = NULL;
        *num_bytes = 0;
        return;
    }

    out = (byte *)calloc(out_len, 1);
    GUARD_ALLOC(out);

    *num_bytes = out_len;
    *bytes = out;

    while (out_len > 0) {
        scan_res = sscanf(hex, "%2x", &byte_val);
        ASSERT(scan_res == 1, "Invalid value in hexadecimal string");
        *out++ = (byte)byte_val;
        hex += 2;
        out_len--;
    }
}

static size_t hex_byte_len(const char *hex)
{
    size_t in_len = 0;

    /*
     * Essentially a portable substitute for strnlen(), for POSIX.1-2001
     * compatibility.
     */
    while (in_len < HEX_TO_BYTES_MAX_STRLEN) {
        if (hex[in_len] == '\0') {
            break;
        }
        in_len++;
    }

    ASSERT(hex[in_len] == '\0', "Input hexadecimal string too long");
    ASSERT(in_len % 2 == 0, "Input hexadecimal string has odd length: %zu",
           in_len);

    return in_len / 2;
}
