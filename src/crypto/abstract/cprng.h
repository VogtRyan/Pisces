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

#ifndef PISCES_CRYPTO_ABSTRACT_CPRNG_H_
#define PISCES_CRYPTO_ABSTRACT_CPRNG_H_

#include "common/bytetype.h"

#include <stddef.h>

struct cprng;

/*
 * Allocates a new psuedorandom number generator. Must be freed with
 * cprng_free_scrub(). Guaranteed to return non-NULL.
 */
struct cprng *cprng_alloc_default(void);

/*
 * Fills the given buffer with random bytes. Guaranteed to succeed, but may
 * block for a finite period of time.
 */
void cprng_bytes(struct cprng *rng, byte *output, size_t output_len);

/*
 * Frees a psuedorandom number generator allocated with cprng_alloc_default()
 * and securely scrubs all memory allocated for it. Calling with NULL is a
 * no-op.
 */
void cprng_free_scrub(struct cprng *rng);

#endif
