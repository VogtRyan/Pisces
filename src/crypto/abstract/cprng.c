/*
 * Copyright (c) 2011-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "cprng.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/random/rarc4.h"
#include "crypto/random/rdev.h"

#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

typedef enum { CPRNG_SOURCE_ARC4RANDOM, CPRNG_SOURCE_DEVRANDOM } cprng_source;

#ifndef PISCES_NO_ARC4RANDOM
#define CPRNG_SOURCE_DEFAULT (CPRNG_SOURCE_ARC4RANDOM)
#else
#define CPRNG_SOURCE_DEFAULT (CPRNG_SOURCE_DEVRANDOM)
#endif

struct cprng {
    cprng_source src;
    int fd;
};

struct cprng *cprng_alloc_default(void)
{
    struct cprng *ret;

    ret = (struct cprng *)calloc(1, sizeof(struct cprng));
    GUARD_ALLOC(ret);

    ret->src = CPRNG_SOURCE_DEFAULT;
    ret->fd = -1;

    return ret;
}

void cprng_bytes(struct cprng *rng, byte *output, size_t output_len)
{
    /* Make too-large requests fail uniformly, regardless of CPRNG source */
    ASSERT(output_len <= SSIZE_MAX, "Read of random data too large");

    switch (rng->src) {
    case CPRNG_SOURCE_ARC4RANDOM:
        rarc4_fill(output, output_len);
        break;
    case CPRNG_SOURCE_DEVRANDOM:
        if (rng->fd < 0) {
            rng->fd = rdev_open();
        }
        rdev_fill(rng->fd, output, output_len);
        break;
    default:
        ASSERT_NEVER_REACH("Invalid CPRNG source");
    }
}

void cprng_free_scrub(struct cprng *rng)
{
    if (rng != NULL) {
        if (rng->fd >= 0) {
            close(rng->fd);
        }
        scrub_memory(rng, sizeof(struct cprng));
        free(rng);
    }
}
