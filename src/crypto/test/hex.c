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
#include <stdio.h>
#include <string.h>

#define UNUSED(varname) (void)(varname)

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

void debug_output_hex(const byte *bytes, size_t len)
{
#ifdef DEBUGGING
    size_t i;

    for (i = 0; i < len; i++) {
        fprintf(DEBUG_OUTPUT, "%02X", bytes[i]);
    }
#else
    UNUSED(bytes);
    UNUSED(len);
#endif
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
