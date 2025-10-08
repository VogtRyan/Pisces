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
 * Allocates a new CHF worker that can queue and run commands on a
 * cryptographic hash context in a separate thread. Guaranteed to return
 * non-NULL. The length parameter specifies the maximum input size that
 * chf_worker_add() will accept.
 *
 * The worker will operate under a single-producer, single-consumer model with
 * a finite-sized queue that blocks when full, so only one thread can call
 * chf_worker_* functions on a given CHF worker.
 *
 * If PISCES_NO_MULTITHREAD is defined, the CHF worker will still adhere to
 * the API described below, but will perform all operations in the current
 * thread instead of spawning a worker thread to perform them.
 */
struct chf_worker *chf_worker_alloc(chf_algorithm alg, size_t max_add_len);

/*
 * Clears the queue of any commands, clears any errors the worker has
 * encountered, then enqueues a CHF-start command to start a new hash
 * operation.
 */
void chf_worker_start(struct chf_worker *chfw);

/*
 * Enqueues a CHF-add command to append the given bytes to the message being
 * hashed. The number of bytes must be less than or equal to the size provided
 * to chf_worker_alloc().
 *
 * Returns the result of the most recently completed CHF-add command: 0 on
 * success, <0 on error (CHF_ERROR_MESSAGE_TOO_LONG). Because the newly queued
 * CHF-add command might not be complete by the time this function returns,
 * error reporting of CHF_ERROR_MESSAGE_TOO_LONG may be delayed until either a
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
 * occurred while executing a CHF-add command or chf_worker_end(). This
 * function may report an error prior to chf_worker_add() or chf_worker_end()
 * returning an error code if a CHF-add command is completed asynchronously.
 */
const char *chf_worker_error(struct chf_worker *chfw);

/*
 * Frees a worker allocated with chf_worker_alloc() and securely scrubs its
 * memory. Calling with NULL is a no-op.
 */
void chf_worker_free_scrub(struct chf_worker *chfw);

#endif
