/*
 * Copyright (c) 2011-2023 Ryan Vogt <rvogt.ca@gmail.com>
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

#include <stddef.h>
#include <stdlib.h>

/*
 * This struct is a hook for different cryptographic pseudorandom number
 * generators that could be implemented. For now, only arc4random is used, as
 * historical concerns about it are largely irrelevant on modern systems.
 *
 * A previous implementation attempted to read from /dev/arandom or
 * /dev/random. That approach made use of the stateful nature of this
 * abstraction. A future implementation could potentially re-add a
 * cprng_algorithm_t that reads from a system device.
 */
typedef enum { CPRNG_ALG_ARC4RANDOM } cprng_algorithm_t;
struct cprng {
    cprng_algorithm_t type;
};

struct cprng *cprng_alloc_default()
{
    struct cprng *ret = (struct cprng *)malloc(sizeof(struct cprng));
    ASSERT_ALLOC(ret);
    ret->type = CPRNG_ALG_ARC4RANDOM;
    return ret;
}

void cprng_bytes(struct cprng *rng, byte_t *bytes, size_t numBytes)
{
    arc4random_buf(bytes, numBytes);
}

void cprng_free_scrub(struct cprng *rng)
{
    if (rng != NULL) {
        scrub_memory(rng, sizeof(struct cprng));
        free(rng);
    }
}
