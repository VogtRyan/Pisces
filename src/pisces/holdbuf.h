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

#define HOLDBUF_ERROR_INSUFFICIENT_DATA (-1)

/*
 * A holdback buffer is a FIFO that retains the most recent stop_size bytes
 * given to it, until holdbuf_end() is called.
 */
struct holdbuf;

/*
 * Allocates a new holdback buffer. Must be freed with holdbuf_free_scrub().
 * Guaranteed to return non-NULL.
 */
struct holdbuf *holdbuf_alloc(size_t stop_size);

/*
 * Adds more bytes to the holdback buffer, returning bytes in FIFO order as
 * more than stop_size bytes fill the buffer. It is guaranteed no more than
 * input_len bytes will be written to the output buffer.
 */
void holdbuf_give(struct holdbuf *hb, const byte *input, size_t input_len,
                  byte *output, size_t *output_len);

/*
 * Empties the reamining stop_size bytes from the holdback buffer. Returns 0 on
 * success, <0 on error (HOLDBUF_ERROR_INSUFFICIENT_DATA).
 */
int holdbuf_end(struct holdbuf *hb, byte *output);

/*
 * Frees a holdback buffer allocated with holdbuf_alloc(), and securely scrubs
 * all memory allocated for the buffer. Calling with NULL is a no-op.
 */
void holdbuf_free_scrub(struct holdbuf *hb);

#endif
