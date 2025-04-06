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

#include "ascii.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/cprng.h"

#include <stddef.h>

void get_ascii(char *result, size_t num)
{
    byte_t *randArray = NULL;
    struct cprng *rng = NULL;
    size_t remaining, toGenerate, i;

    /* Allocate a temporary array to store raw random bytes */
    remaining = num;
    randArray = (byte_t *)malloc(num);
    GUARD_ALLOC(randArray);
    rng = cprng_alloc_default();

    /*
     * Generate random bytes and convert to characters.  Since there are 94
     * legal characters (ASCII 33 to 126 -- we omit the space at ASCII 32), we
     * can use 94*2 = 188/256 possible values of a byte to generate a character
     * without biasing the password.
     */
    while (remaining > 0) {
        toGenerate = remaining;
        cprng_bytes(rng, randArray, toGenerate);
        for (i = 0; i < toGenerate; i++) {
            if (randArray[i] < 188) {
                *result = (char)((int)randArray[i] % 94 + 33);
                remaining--;
                result++;
            }
        }
    }

    cprng_free_scrub(rng);
    scrub_memory(randArray, num);
    free(randArray);
}

void get_alpha_num(char *result, size_t num)
{
    byte_t *randArray = NULL;
    struct cprng *rng = NULL;
    size_t remaining, toGenerate, i;

    /* Allocate a temporary array to store raw random bytes */
    remaining = num;
    randArray = (byte_t *)malloc(num);
    GUARD_ALLOC(randArray);
    rng = cprng_alloc_default();

    /*
     * Generate random bytes and convert to characters.  Since there are 62
     * legal characters, we can use 62*4 = 248/256 possible values of a byte to
     * generate a character without biasing the password.
     */
    while (remaining > 0) {
        toGenerate = remaining;
        cprng_bytes(rng, randArray, toGenerate);
        for (i = 0; i < toGenerate; i++) {
            if (randArray[i] >= 248) {
                continue;
            }
            if (randArray[i] < 104) {
                /* Lower case letters */
                *result = (char)((int)randArray[i] % 26 + 97);
            }
            else if (randArray[i] < 208) {
                /* Upper case letters */
                *result = (char)((int)randArray[i] % 26 + 65);
            }
            else {
                /* Numbers */
                *result = (char)((int)randArray[i] % 10 + 48);
            }
            remaining--;
            result++;
        }
    }

    cprng_free_scrub(rng);
    scrub_memory(randArray, num);
    free(randArray);
}
