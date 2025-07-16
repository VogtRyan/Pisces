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
 * Allocates a new worker that can queue and run commands on a cryptographic
 * hash context. Guaranteed to return non-NULL. The worker takes ownership of
 * the CHF context, and no further calls should be made directly on it.
 *
 * If input_buf_size is greater than 0, the worker will spawn a helper thread
 * to execute queued CHF commands, instead of executing them immediately. In
 * this case, the maximum message size chf_worker_add() can accept will be
 * input_buf_size. The thread will operate under a single-producer,
 * single-consumer model.
 */
struct chf_worker *chf_worker_alloc(struct chf_ctx *ctx,
                                    size_t input_buf_size);

/*
 * Clears the queue of any commands the worker has not completed, clears any
 * errors the worker has encountered, and enqueues a command to start a new
 * hash operation.
 */
void chf_worker_start(struct chf_worker *chfw);

/*
 * Enqueues a command to append the given bytes to the message being hashed.
 * If the worker was allocated with a non-zero buffer size, msg_len must be
 * less than or equal to that buffer size. This function will block on the CHF
 * context's computation if the queue is full.
 *
 * Returns the result of the most recently completed CHF add command: 0 on
 * success, <0 on error (CHF_ERROR_MESSAGE_TOO_LONG). Because the newly queued
 * add command might not be complete by the time this function returns, error
 * reporting of CHF_ERROR_MESSAGE_TOO_LONG may be delayed until either a
 * subsequent chf_worker_add() call or the call to chf_worker_end().
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
 * occurred while executing a CHF add or end command. Because commands may be
 * executed in the background in a multithreaded environment,
 * chf_worker_error() may report an error prior to chf_worker_add() or
 * chf_worker_end() returning an error code.
 */
const char *chf_worker_error(struct chf_worker *chfw);

/*
 * Frees a worker allocated with chf_worker_alloc(), securely scrubs its
 * memory, and terminates its helper thread if it spawned one. Also frees the
 * CHF context that the worker took ownership of and securely scrubs all of its
 * memory. Calling with NULL is a no-op.
 */
void chf_worker_free_scrub(struct chf_worker *chfw);

#endif
