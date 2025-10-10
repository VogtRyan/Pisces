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

#ifndef PISCES_PISCES_HOLDBACK_BUFFER_H_
#define PISCES_PISCES_HOLDBACK_BUFFER_H_

#include "common/bytetype.h"

#include <stddef.h>

#define HOLDBACK_BUFFER_ERROR_INSUFFICIENT_DATA (-1)

/*
 * A buffer that returns bytes in FIFO order, as the number of bytes added to
 * the buffer exceeds its holdback size.
 */
struct holdback_buffer;

/*
 * Allocates a new holdback buffer. Must be freed with
 * holdback_buffer_free_scrub(). Guaranteed to return non-NULL.
 */
struct holdback_buffer *holdback_buffer_alloc(size_t holdback_size);

/*
 * Appends the given bytes to the end of the buffer, outputting bytes in FIFO
 * order as the number of bytes in the buffer exceeds its holdback size.
 * Guaranteed to write no more than input_len bytes to the output buffer.
 */
void holdback_buffer_append(struct holdback_buffer *hb, const byte *input,
                            size_t input_len, byte *output,
                            size_t *output_len);

/*
 * Empties the holdback buffer, outputting a number of bytes equal to its
 * holdback size. Returns 0 on success, <0 on error
 * (HOLDBACK_BUFFER_ERROR_INSUFFICIENT_DATA).
 */
int holdback_buffer_finalize(struct holdback_buffer *hb, byte *output);

/*
 * Frees a holdback buffer allocated with holdback_buffer_alloc(), and securely
 * scrubs all memory allocated for the buffer. Calling with NULL is a no-op.
 */
void holdback_buffer_free_scrub(struct holdback_buffer *hb);

#endif
