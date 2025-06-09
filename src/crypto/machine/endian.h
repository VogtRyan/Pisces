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

#ifndef PISCES_CRYPTO_MACHINE_ENDIAN_H_
#define PISCES_CRYPTO_MACHINE_ENDIAN_H_

#include "common/bytetype.h"

#include <stdint.h>

/*
 * Platform-independent code for interpreting sequences of raw bytes as
 * unsigned integers stored in big-endian or little-endian order.
 *
 * The put_* functions store integer values to memory in big/little-endian
 * order, and the read_* functions read integer values from memory that were
 * stored in big/little-endian order.
 */

static inline void put_big_end_32(byte *location, uint32_t value)
{
    /* clang-format off */
    location[0] = (byte)((value >> 24) & 0xFF);
    location[1] = (byte)((value >> 16) & 0xFF);
    location[2] = (byte)((value >>  8) & 0xFF);
    location[3] = (byte)((value      ) & 0xFF);
    /* clang-format on */
}

static inline void put_big_end_64(byte *location, uint64_t value)
{
    /* clang-format off */
    location[0] = (byte)((value >> 56) & 0xFF);
    location[1] = (byte)((value >> 48) & 0xFF);
    location[2] = (byte)((value >> 40) & 0xFF);
    location[3] = (byte)((value >> 32) & 0xFF);
    location[4] = (byte)((value >> 24) & 0xFF);
    location[5] = (byte)((value >> 16) & 0xFF);
    location[6] = (byte)((value >>  8) & 0xFF);
    location[7] = (byte)((value      ) & 0xFF);
    /* clang-format on */
}

static inline void put_little_end_32(byte *location, uint32_t value)
{
    /* clang-format off */
    location[0] = (byte)((value      ) & 0xFF);
    location[1] = (byte)((value >>  8) & 0xFF);
    location[2] = (byte)((value >> 16) & 0xFF);
    location[3] = (byte)((value >> 24) & 0xFF);
    /* clang-format on */
}

static inline void put_little_end_64(byte *location, uint64_t value)
{
    /* clang-format off */
    location[0] = (byte)((value      ) & 0xFF);
    location[1] = (byte)((value >>  8) & 0xFF);
    location[2] = (byte)((value >> 16) & 0xFF);
    location[3] = (byte)((value >> 24) & 0xFF);
    location[4] = (byte)((value >> 32) & 0xFF);
    location[5] = (byte)((value >> 40) & 0xFF);
    location[6] = (byte)((value >> 48) & 0xFF);
    location[7] = (byte)((value >> 56) & 0xFF);
    /* clang-format on */
}

static inline uint32_t get_big_end_32(const byte *location)
{
    /* clang-format off */
    return (((uint32_t)(location[0])) << 24) |
           (((uint32_t)(location[1])) << 16) |
           (((uint32_t)(location[2])) <<  8) |
           (((uint32_t)(location[3]))      );
    /* clang-format on */
}

static inline uint64_t get_big_end_64(const byte *location)
{
    /* clang-format off */
    return (((uint64_t)(location[0])) << 56) |
           (((uint64_t)(location[1])) << 48) |
           (((uint64_t)(location[2])) << 40) |
           (((uint64_t)(location[3])) << 32) |
           (((uint64_t)(location[4])) << 24) |
           (((uint64_t)(location[5])) << 16) |
           (((uint64_t)(location[6])) <<  8) |
           (((uint64_t)(location[7]))      );
    /* clang-format on */
}

static inline uint32_t get_little_end_32(const byte *location)
{
    /* clang-format off */
    return (((uint32_t)(location[0]))      ) |
           (((uint32_t)(location[1])) <<  8) |
           (((uint32_t)(location[2])) << 16) |
           (((uint32_t)(location[3])) << 24);
    /* clang-format on */
}

static inline uint64_t get_little_end_64(const byte *location)
{
    /* clang-format off */
    return (((uint64_t)(location[0]))      ) |
           (((uint64_t)(location[1])) <<  8) |
           (((uint64_t)(location[2])) << 16) |
           (((uint64_t)(location[3])) << 24) |
           (((uint64_t)(location[4])) << 32) |
           (((uint64_t)(location[5])) << 40) |
           (((uint64_t)(location[6])) << 48) |
           (((uint64_t)(location[7])) << 56);
    /* clang-format on */
}

#endif
