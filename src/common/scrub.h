/*
 * Copyright (c) 2008-2023 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_COMMON_SCRUB_H_
#define PISCES_COMMON_SCRUB_H_

#include "bytetype.h"

#include <stddef.h>

/*
 * Zero out the memory at the given location, in a manner that should not be
 * optimized out by the compiler. Note, the function can still be inlined.
 *
 * For a detailed discussion about further optimizing this function, see
 * "Zero'ing memory, compiler optimizations and memset_s", written by
 * David Wong on www.cryptologie.net, August 2017.
 */
static inline void scrub_memory(void *location, size_t num_bytes)
{
    volatile byte_t *p = location;
    while (num_bytes--) {
        *p = (byte_t)0;
        p++;
    }
}

#endif
