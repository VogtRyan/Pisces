/*
 * Copyright (c) 2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_CRYPTO_ALGORITHMS_ARGON2_MESSAGE_BARRIER_H_
#define PISCES_CRYPTO_ALGORITHMS_ARGON2_MESSAGE_BARRIER_H_

#include <stddef.h>

/*
 * A cyclic barrier with a single-slot message buffer that gets cleared when
 * the barrier is tripped.
 */
struct message_barrier;

/*
 * Allocates a barrier in its first cyclic generation with no data in its
 * message buffer. Guaranteed to return non-NULL.
 */
struct message_barrier *message_barrier_alloc(size_t num_threads);

/*
 * Returns the value in the barrier's message buffer, blocking if necessary
 * until a message is written into the buffer.
 */
int message_barrier_read(struct message_barrier *barrier);

/*
 * Waits at the barrier until all threads arrive in this generation. After all
 * threads have arrived: the message buffer is cleared, and the barrier resets
 * and can be reused for another generation.
 */
void message_barrier_wait(struct message_barrier *barrier);

/*
 * Writes the given value into the barrier's message buffer. Once a value is
 * present in the message buffer, no further data can be written to it.
 * However, the message buffer can be cleared using message_barrier_wait().
 */
void message_barrier_write(struct message_barrier *barrier, int message);

/*
 * Frees a barrier allocated by message_barrier_alloc(). Calling with NULL is
 * a no-op.
 */
void message_barrier_free(struct message_barrier *barrier);

#endif
