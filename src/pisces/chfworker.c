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

#include "chfworker.h"

#include "common/bytetype.h"
#include "common/config.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/chf.h"

#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define COMMAND_NONE             (0)
#define COMMAND_START            (1)
#define COMMAND_ADD              (2)
#define COMMAND_TERMINATE_THREAD (3)

struct chf_worker {
    struct chf_ctx *ctx;
    byte *input_buf;
    pthread_t worker;
    pthread_cond_t command_change;
    pthread_mutex_t mtx;
    size_t input_len;
    size_t input_buf_size;
    size_t digest_size;
    int command;
    int errcode;
};

static void *helper_thread_main(void *chfw_arg);

struct chf_worker *chf_worker_alloc(struct chf_ctx *ctx, size_t input_buf_size)
{
    struct chf_worker *chfw;

    chfw = (struct chf_worker *)calloc(1, sizeof(struct chf_worker));
    GUARD_ALLOC(chfw);

    chfw->ctx = ctx;
    chfw->digest_size = chf_digest_size(chfw->ctx);

    if (input_buf_size == 0) {
        return chfw;
    }

    chfw->input_buf = (byte *)calloc(input_buf_size, sizeof(byte));
    GUARD_ALLOC(chfw->input_buf);
    chfw->input_buf_size = input_buf_size;

    if (pthread_mutex_init(&(chfw->mtx), NULL)) {
        FATAL_ERROR("Could not initialize pthread mutex");
    }
    if (pthread_cond_init(&(chfw->command_change), NULL)) {
        FATAL_ERROR("Could not initialize pthread condition variable");
    }
    if (pthread_create(&(chfw->worker), NULL, helper_thread_main, chfw)) {
        FATAL_ERROR("Could not create pthread");
    }

    return chfw;
}

void chf_worker_start(struct chf_worker *chfw)
{
    if (chfw->input_buf_size == 0) {
        chf_start(chfw->ctx);
        return;
    }

    /* Clear the queue by blocking on computation in the helper thread */
    pthread_mutex_lock(&(chfw->mtx));
    while (chfw->command != COMMAND_NONE) {
        pthread_cond_wait(&(chfw->command_change), &(chfw->mtx));
    }

    chfw->errcode = 0;
    chfw->command = COMMAND_START;
    pthread_cond_signal(&(chfw->command_change));

    pthread_mutex_unlock(&(chfw->mtx));
}

int chf_worker_add(struct chf_worker *chfw, const byte *msg, size_t msg_len)
{
    int ret;

    if (chfw->input_buf_size == 0) {
        return chf_add(chfw->ctx, msg, msg_len);
    }

    ASSERT(msg_len <= chfw->input_buf_size,
           "chf_worker_add message length too large: %zu", msg_len);

    /*
     * Enqueue at most one chf_start or chf_add command at a time, blocking
     * until any commands already in the queue are complete.
     */
    pthread_mutex_lock(&(chfw->mtx));
    while (chfw->command != COMMAND_NONE) {
        pthread_cond_wait(&(chfw->command_change), &(chfw->mtx));
    }

    /*
     * Return the result of any previous call to chf_add(). The only error that
     * chf_add() can return is that the input message is too long. We can delay
     * reporting that error condition, and the caller will still eventually see
     * it -- either from the next call to chf_worker_add(), or from
     * chf_worker_end().
     */
    ret = chfw->errcode;

    if (chfw->errcode == 0) {
        memcpy(chfw->input_buf, msg, msg_len);
        chfw->input_len = msg_len;
        chfw->command = COMMAND_ADD;
        pthread_cond_signal(&(chfw->command_change));
    }

    pthread_mutex_unlock(&(chfw->mtx));
    return ret;
}

int chf_worker_end(struct chf_worker *chfw, byte *digest)
{
    int ret;

    if (chfw->input_buf_size == 0) {
        return chf_end(chfw->ctx, digest);
    }

    pthread_mutex_lock(&(chfw->mtx));
    while (chfw->command != COMMAND_NONE) {
        pthread_cond_wait(&(chfw->command_change), &(chfw->mtx));
    }

    /*
     * Because we are in a single-producer, single-consumer model, we can
     * assume that no more data is being input to the hash operation once we
     * get the command-change signal above.
     */
    if (chfw->errcode == 0) {
        chfw->errcode = chf_end(chfw->ctx, digest);
    }
    ret = chfw->errcode;

    pthread_mutex_unlock(&(chfw->mtx));
    return ret;
}

size_t chf_worker_digest_size(const struct chf_worker *chfw)
{
    return chfw->digest_size;
}

const char *chf_worker_error(struct chf_worker *chfw)
{
    const char *errmsg;

    if (chfw->input_buf_size == 0) {
        return chf_error(chfw->ctx);
    }

    pthread_mutex_lock(&(chfw->mtx));
    while (chfw->command != COMMAND_NONE) {
        pthread_cond_wait(&(chfw->command_change), &(chfw->mtx));
    }

    switch (chfw->errcode) {
    case CHF_ERROR_MESSAGE_TOO_LONG:
        errmsg = "Message length exceeded threaded CHF maximum";
        break;
    default:
        ASSERT_NEVER_REACH("Invalid threaded CHF error code");
    }

    pthread_mutex_unlock(&(chfw->mtx));
    return errmsg;
}

void chf_worker_free_scrub(struct chf_worker *chfw)
{
    if (chfw == NULL) {
        return;
    }

    if (chfw->input_buf_size != 0) {
        pthread_mutex_lock(&(chfw->mtx));
        while (chfw->command != COMMAND_NONE) {
            pthread_cond_wait(&(chfw->command_change), &(chfw->mtx));
        }

        chfw->command = COMMAND_TERMINATE_THREAD;
        pthread_cond_signal(&(chfw->command_change));
        pthread_mutex_unlock(&(chfw->mtx));

        /*
         * The main thread does not need the worker to indicate the termination
         * task is complete (by resetting the command varaible and signalling).
         * The termination command is given nowhere but here, and the worker
         * thread is guaranteed to terminate upon receiving it.
         */
        pthread_join(chfw->worker, NULL);

        pthread_cond_destroy(&(chfw->command_change));
        pthread_mutex_destroy(&(chfw->mtx));
    }

    chf_free_scrub(chfw->ctx);
    if (chfw->input_buf != NULL) {
        scrub_memory(chfw->input_buf, chfw->input_buf_size);
        free(chfw->input_buf);
    }
    scrub_memory(chfw, sizeof(struct chf_worker));
    free(chfw);
}

static void *helper_thread_main(void *chfw_arg)
{
    struct chf_worker *chfw;
    int errcode;

    chfw = (struct chf_worker *)chfw_arg;

    while (1) {
        pthread_mutex_lock(&(chfw->mtx));
        while (chfw->command == COMMAND_NONE) {
            pthread_cond_wait(&(chfw->command_change), &(chfw->mtx));
        }
        pthread_mutex_unlock(&(chfw->mtx));

        if (chfw->command == COMMAND_TERMINATE_THREAD) {
            /*
             * No need to indicate to the main thread that we have completed
             * the termination command. A deadlock could occur only if the main
             * thread tries to queue a command after calling chf_worker_free().
             */
            break;
        }
        else if (chfw->command == COMMAND_START) {
            chf_start(chfw->ctx);
            errcode = 0;
        }
        else {
            errcode = chf_add(chfw->ctx, chfw->input_buf, chfw->input_len);
        }

        pthread_mutex_lock(&(chfw->mtx));
        chfw->errcode = errcode;
        chfw->command = COMMAND_NONE;
        pthread_cond_signal(&(chfw->command_change));
        pthread_mutex_unlock(&(chfw->mtx));
    }

    return NULL;
}
