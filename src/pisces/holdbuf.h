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

#ifndef PISCES_PISCES_HOLDBUF_H_
#define PISCES_PISCES_HOLDBUF_H_

#include "common/bytetype.h"

#include <stddef.h>

/*
 * The error if there is insufficient data to conclude the holdbuf_end()
 * operation.
 */
#define HOLDBUF_ERROR_INSUFFICIENT_DATA (-1)

/*
 * This structure holds the most recent fix number of bytes given to it, in
 * FIFO order.
 */
struct holdbuf;

/*
 * Allocates a new holdback buffer. Must be freed with holdbuf_free_scrub().
 * Guaranteed to return non-NULL; it is a fatal error for allocation to fail.
 */
struct holdbuf *holdbuf_alloc(size_t stopSize);

/*
 * Give the numBytes in bytes to the holdback buffer. If the buffer overflows
 * past stopSize, return (as a FIFO) some bytes to the caller. The bytes will
 * be placed in output, with outputBytes being set to the amount given back. It
 * is guaranteed that no more than numBytes will be written to output.
 */
void holdbuf_give(struct holdbuf *hb, const byte *bytes, size_t numBytes,
                  byte *output, size_t *outputBytes);

/*
 * Empties the reamining stopSize bytes into the given output buffer. Returns 0
 * on success, or HOLDBUF_ERROR_INSUFFICIENT_DATA if there are not enough bytes
 * in the buffer.
 */
int holdbuf_end(struct holdbuf *hb, byte *output);

/*
 * Frees a holdback buffer allocated with holdbuf_alloc(), and securely scrubs
 * all memory allocated for the buffer. Calling with NULL is a no-op.
 */
void holdbuf_free_scrub(struct holdbuf *hb);

#endif
