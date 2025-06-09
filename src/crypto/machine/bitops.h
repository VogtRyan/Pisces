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

#ifndef PISCES_CRYPTO_MACHINE_BITOPS_H_
#define PISCES_CRYPTO_MACHINE_BITOPS_H_

#include "common/bytetype.h"

#include <stdint.h>

/*
 * Circular left and right bit shifts. Calling any function with a negative
 * shift amount produces a shift in the opposite direction (e.g., calling a
 * circular left shift by 10 bits produces the same result as a calling a
 * circular right shift by -10 bits).
 */

static inline uint32_t circ_shift_left_32(uint32_t value, int amount)
{
    amount &= 31;
    if (amount == 0) {
        return value;
    }
    return (value << amount) | (value >> (32 - amount));
}

static inline uint64_t circ_shift_left_64(uint64_t value, int amount)
{
    amount &= 63;
    if (amount == 0) {
        return value;
    }
    return (value << amount) | (value >> (64 - amount));
}

static inline uint32_t circ_shift_right_32(uint32_t value, int amount)
{
    amount &= 31;
    if (amount == 0) {
        return value;
    }
    return (value >> amount) | (value << (32 - amount));
}

static inline uint64_t circ_shift_right_64(uint64_t value, int amount)
{
    amount &= 63;
    if (amount == 0) {
        return value;
    }
    return (value >> amount) | (value << (64 - amount));
}

#endif
