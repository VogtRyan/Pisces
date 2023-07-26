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

#ifndef PISCES_CRYPTO_MACHINE_ENDIAN_H_
#define PISCES_CRYPTO_MACHINE_ENDIAN_H_

#include "common/bytetype.h"

#include <stdint.h>

/*
 * This file contains platform-independent code for interpreting sequences of
 * bytes as big-endian or little-endian integers, which is an operation that
 * cryptographic primitive specifications frequently dictate.
 *
 * It would be possible to optimize this code to take advantage of a system's
 * innate endianness. The endian-neutral code, below, introduces a performance
 * penalty. However, endian-specific code introduces a significant portability
 * penalty. Macro names, and even header names, are not standardized (when they
 * exist at all). Runtime detection of endianness can be unreliable on dynamic-
 * endian platforms, etc.
 *
 * The goal of this project is portable, correct code, as opposed to
 * high-performance code. The decision not to attempt to optimize these
 * functions was made purposefully.
 */

/*
 * Write the given 32-bit integer value into the given address in memory in
 * big-endian order. On a big-endian machine, it would be equivalent to:
 *
 *     *((uint32_t *)location) = value;
 */
static inline void put_big_end_32(byte_t *location, uint32_t value)
{
    location[0] = (byte_t)((value >> 24) & 0xFF);
    location[1] = (byte_t)((value >> 16) & 0xFF);
    location[2] = (byte_t)((value >>  8) & 0xFF);
    location[3] = (byte_t)((value      ) & 0xFF);
}

/*
 * Write the given 64-bit integer value into the given address in memory in
 * big-endian order. On a big-endian machine, it would be equivalent to:
 *
 *     *((uint64_t *)location) = value;
 */
static inline void put_big_end_64(byte_t *location, uint64_t value)
{
    location[0] = (byte_t)((value >> 56) & 0xFF);
    location[1] = (byte_t)((value >> 48) & 0xFF);
    location[2] = (byte_t)((value >> 40) & 0xFF);
    location[3] = (byte_t)((value >> 32) & 0xFF);
    location[4] = (byte_t)((value >> 24) & 0xFF);
    location[5] = (byte_t)((value >> 16) & 0xFF);
    location[6] = (byte_t)((value >>  8) & 0xFF);
    location[7] = (byte_t)((value      ) & 0xFF);
}

/*
 * Write the given 32-bit integer value into the given address in memory in
 * little-endian order. On a little-endian machine, it would be equivalent to:
 *
 *     *((uint32_t *)location) = value;
 */
static inline void put_little_end_32(byte_t *location, uint32_t value)
{
    location[0] = (byte_t)((value      ) & 0xFF);
    location[1] = (byte_t)((value >>  8) & 0xFF);
    location[2] = (byte_t)((value >> 16) & 0xFF);
    location[3] = (byte_t)((value >> 24) & 0xFF);
}

/*
 * Write the given 64-bit integer value into the given address in memory in
 * little-endian order. On a little-endian machine, it would be equivalent to:
 *
 *     *((uint64_t *)location) = value;
 */
static inline void put_little_end_64(byte_t *location, uint64_t value)
{
    location[0] = (byte_t)((value      ) & 0xFF);
    location[1] = (byte_t)((value >>  8) & 0xFF);
    location[2] = (byte_t)((value >> 16) & 0xFF);
    location[3] = (byte_t)((value >> 24) & 0xFF);
    location[4] = (byte_t)((value >> 32) & 0xFF);
    location[5] = (byte_t)((value >> 40) & 0xFF);
    location[6] = (byte_t)((value >> 48) & 0xFF);
    location[7] = (byte_t)((value >> 56) & 0xFF);
}

/*
 * Interpret the 32 bits bytes at the given memory address as a big-endian
 * integer and return its value.  On a big-endian machine, it would be
 * equivalent to:
 *
 *     return *((uint32_t *)location);
 */
static inline uint32_t get_big_end_32(const byte_t *location)
{
    return (((uint32_t)(location[0])) << 24) |
           (((uint32_t)(location[1])) << 16) |
           (((uint32_t)(location[2])) <<  8) |
           (((uint32_t)(location[3]))      );
}

/*
 * Interpret the 64 bits bytes at the given memory address as a big-endian
 * integer and return its value. On a big-endian machine, it would be
 * equivalent to:
 *
 *     return *((uint64_t *)location);
 */
static inline uint64_t get_big_end_64(const byte_t *location)
{
    return (((uint64_t)(location[0])) << 56) |
           (((uint64_t)(location[1])) << 48) |
           (((uint64_t)(location[2])) << 40) |
           (((uint64_t)(location[3])) << 32) |
           (((uint64_t)(location[4])) << 24) |
           (((uint64_t)(location[5])) << 16) |
           (((uint64_t)(location[6])) <<  8) |
           (((uint64_t)(location[7]))      );
}

/*
 * Interpret the 32 bits bytes at the given memory address as a little-endian
 * integer and return its value. On a little-endian machine, it would be
 * equivalent to:
 *
 *     return *((uint32_t *)location);
 */
static inline uint32_t get_little_end_32(const byte_t *location)
{
    return (((uint32_t)(location[0]))      ) |
           (((uint32_t)(location[1])) <<  8) |
           (((uint32_t)(location[2])) << 16) |
           (((uint32_t)(location[3])) << 24);
}

/*
 * Interpret the 64 bits bytes at the given memory address as a little-endian
 * integer and return its value. On a little-endian machine, it would be
 * equivalent to:
 *
 *     return *((uint64_t *)location);
 */
static inline uint64_t get_little_end_64(const byte_t *location)
{
    return (((uint64_t)(location[0]))      ) |
           (((uint64_t)(location[1])) <<  8) |
           (((uint64_t)(location[2])) << 16) |
           (((uint64_t)(location[3])) << 24) |
           (((uint64_t)(location[4])) << 32) |
           (((uint64_t)(location[5])) << 40) |
           (((uint64_t)(location[6])) << 48) |
           (((uint64_t)(location[7])) << 56);
}

#endif
