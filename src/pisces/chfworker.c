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
#define COMMAND_CHF_START        (1)
#define COMMAND_CHF_ADD          (2)
#define COMMAND_TERMINATE_THREAD (3)

/*
 * When input_buf_size == 0, the worker operates single-threaded and executes
 * commands immediately. Otherwise, input_buf can buffer message data for a
 * single CHF add command. A worker can buffer at most one command.
 */
struct chf_worker {
    struct chf_ctx *ctx;
    byte *input_buf;
    pthread_t helper;
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
        FATAL_ERROR("Could not initialize chfworker mutex");
    }
    if (pthread_cond_init(&(chfw->command_change), NULL)) {
        FATAL_ERROR("Could not initialize chfworker condition variable");
    }
    if (pthread_create(&(chfw->helper), NULL, helper_thread_main, chfw)) {
        FATAL_ERROR("Could not create chfworker helper thread");
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

    /*
     * Reset the error code immediately, to make the behaviour of
     * chf_worker_error() consistent with chf_worker_start() having been
     * called -- otherwise, we would have to block in chf_worker_error() until
     * the queued CHF start command executes.
     */
    chfw->errcode = 0;
    chfw->command = COMMAND_CHF_START;
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

    /* Block on computation until we can enqueue the CHF add command */
    pthread_mutex_lock(&(chfw->mtx));
    while (chfw->command != COMMAND_NONE) {
        pthread_cond_wait(&(chfw->command_change), &(chfw->mtx));
    }

    /*
     * Return the result of any previous call to chf_add(), which delays error
     * reporting by one CHF add command or until chf_worker_end() is called.
     */
    ret = chfw->errcode;

    if (chfw->errcode == 0) {
        memcpy(chfw->input_buf, msg, msg_len);
        chfw->input_len = msg_len;
        chfw->command = COMMAND_CHF_ADD;
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
         * The helper thread does not signal to indicate the termination
         * command is complete; it just terminates.
         */
        pthread_join(chfw->helper, NULL);

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
            break;
        }
        else if (chfw->command == COMMAND_CHF_START) {
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
