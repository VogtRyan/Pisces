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

#include <math.h>
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

double bits_security_ascii(size_t num)
{
    /* log_2(94^n) == n * log_2(94) */
    return num * log2(94);
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

double bits_security_alpha_num(size_t num)
{
    /* log_2(62^n) == n * log_2(62) */
    return num * log2(62);
}

void get_numeric(char *result, size_t num)
{
    byte_t *randArray;
    struct cprng *rng;
    size_t rawSize, rawSizeMax, i;

    /*
     * Allocate a temporary array to store raw random bytes. We can potentially
     * extract two random characters from each random byte.
     */
    rawSizeMax = num / 2;
    if (num & 0x1) {
        rawSizeMax++;
    }
    randArray = (byte_t *)malloc(rawSizeMax);
    GUARD_ALLOC(randArray);
    rng = cprng_alloc_default();

    /*
     * If any random byte is less than 200, we can extract two unbiased values
     * in the range 0-9 from it: the ones digit, and the floored remainder
     * when it's divided by 20.
     *
     * If the random byte is in the range [200, 249], we can extract one
     * unbiased value from it: the ones digit.
     */
    while (num > 0) {
        rawSize = num / 2;
        if (num & 0x1) {
            rawSize++;
        }
        cprng_bytes(rng, randArray, rawSize);
        for (i = 0; i < rawSize; i++) {
            if (randArray[i] < 250) {
                *result = '0' + (char)(randArray[i] % 10);
                result++;
                num--;
            }
            if (num > 0 && randArray[i] < 200) {
                *result = '0' + (char)(randArray[i] / 20);
                result++;
                num--;
            }
        }
    }

    cprng_free_scrub(rng);
    scrub_memory(randArray, rawSizeMax);
    free(randArray);
}

double bits_security_numeric(size_t num)
{
    /* log_2(10^n) == n * log_2(10) */
    return num * log2(10);
}
