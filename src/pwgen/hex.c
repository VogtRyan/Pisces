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

#include "hex.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/cprng.h"

#include <stddef.h>

/*
 * Fills the result with the given number of hex characters, using tenChar as
 * the base character for values between 10 and 15.
 */
static void get_hex_chars(char *result, size_t num, char tenChar);

void get_hex_lowercase(char *result, size_t num)
{
    get_hex_chars(result, num, 'a');
}

void get_hex_uppercase(char *result, size_t num)
{
    get_hex_chars(result, num, 'A');
}

static void get_hex_chars(char *result, size_t num, char tenChar)
{
    byte_t *randArray = NULL;
    struct cprng *rng = NULL;
    byte_t current;
    size_t rawSize;
    int moveRaw, i;

    /* Allocate a temporary array to store raw random bytes */
    rawSize = num / 2;
    if (num & 0x1) {
        rawSize++;
    }
    randArray = (byte_t *)malloc(rawSize);
    GUARD_ALLOC(randArray);

    /*
     * Generate random bytes and convert to characters.  We get two unbiased
     * hex characters for every byte generated.
     */
    rng = cprng_alloc_default();
    cprng_bytes(rng, randArray, rawSize);
    moveRaw = i = 0;
    while (num > 0) {
        current = (byte_t)(randArray[i] & 0x0F);
        if (current <= (byte_t)9) {
            *result = '0' + (char)current;
        }
        else {
            *result = tenChar + (char)current - (char)10;
        }
        result++;
        num--;
        if (moveRaw) {
            i++;
            moveRaw = 0;
        }
        else {
            randArray[i] >>= 4;
            moveRaw = 1;
        }
    }

    cprng_free_scrub(rng);
    scrub_memory(randArray, rawSize);
    free(randArray);
}
