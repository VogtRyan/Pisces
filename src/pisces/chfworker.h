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

#ifndef PISCES_PISCES_CHFWORKER_H_
#define PISCES_PISCES_CHFWORKER_H_

#include <stddef.h>

#include "common/bytetype.h"
#include "crypto/abstract/chf.h"

struct chf_worker;

/*
 * Allocates a new worker that can run a cryptographic hash operation. Does
 * not automatically start a new hash operation. Must be freed with
 * chf_worker_free_scrub(). Guaranteed to return non-NULL.
 *
 * If input_buf_size is greater than 0, a buffer will be allocated to queue
 * underlying CHF commands and run them in another thread. The data size of CHF
 * add commands is bounded by input_buf_size if it is greater than 0. The
 * thread operates under a single-producer, single-consumer model: only a
 * single thread can provide work to the worker.
 *
 * The new worker takes ownership of the CHF context, and is responsible for
 * freeing it. An idiom for using chf_worker correctly, whether the buffer size
 * is positive or zero, is:
 *
 *     chf_worker w = chf_worker_alloc(chf_alloc(...), INPUT_BUF_SIZE);
 *     chf_worker_start(w);
 *     ...
 *     chf_worker_free_scrub(w);
 */
struct chf_worker *chf_worker_alloc(struct chf_ctx *ctx,
                                    size_t input_buf_size);

/*
 * Clears the queue of any commands the worker has not completed, clears any
 * errors the worker has encountered, and enqueues a command to start a new
 * hash computation.
 */
void chf_worker_start(struct chf_worker *chfw);

/*
 * Enqueues a command to append the given bytes to the message being hashed.
 * If the worker was allocated with a positive buffer size, the length of the
 * data being appended must be less than or equal to that size.
 *
 * Returns the result of the most recently completed CHF add command: 0 on
 * success, <0 on error (CHF_ERROR_MESSAGE_TOO_LONG). Because this add
 * command is not guaranteed to be complete by the time this function
 * returns, error reporting of CHF_ERROR_MESSAGE_TOO_LONG may be delayed until
 * either a subsequent chf_worker_add() call or the call to chf_worker_end().
 */
int chf_worker_add(struct chf_worker *chfw, const byte *msg, size_t msg_len);

/*
 * Completes all queued commands and computes the message digest. The size of
 * the digest will be equal to chf_worker_digest_size(), which is guaranteed
 * not to exceed CHF_MAX_DIGEST_SIZE. Returns 0 on success, <0 on error
 * (CHF_ERROR_MESSAGE_TOO_LONG).
 */
int chf_worker_end(struct chf_worker *chfw, byte *digest);

/*
 * Returns the size of the hash algorithm's digest output. Guaranteed to be
 * greater than zero and no larger than CHF_MAX_DIGEST_SIZE.
 */
size_t chf_worker_digest_size(const struct chf_worker *chfw);

/*
 * Returns a human-readable description of the most recent error that has
 * occurred while processing queued commands or executing the CHF end command.
 * Because commands may be executed in the background in a multithreaded
 * environment, chf_worker_error() may report an error prior to
 * chf_worker_add() or chf_worker_end() returning an error code.
 */
const char *chf_worker_error(struct chf_worker *chfw);

/*
 * Frees a worker allocated with chf_worker_alloc(). securely scrubs all its
 * memory, and terminates any additional threads it has created. Also frees the
 * CHF context that the worker took ownership of, and securely scrubs all of
 * its memory. Calling with NULL is a no-op.
 */
void chf_worker_free_scrub(struct chf_worker *chfw);

#endif
