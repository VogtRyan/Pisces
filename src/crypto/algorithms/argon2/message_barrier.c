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

#include "message_barrier.h"

#include "common/errorflow.h"

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

struct message_barrier {
    pthread_cond_t barrier_tripped;
    pthread_cond_t message_written;
    pthread_mutex_t mtx;
    size_t num_reached;
    size_t num_threads;
    int message;
    bool message_present;
    bool odd_even_generation;
};

struct message_barrier *message_barrier_alloc(size_t num_threads)
{
    struct message_barrier *ret;

    ASSERT(num_threads > 0, "Cannot create message barrier for zero threads");

    ret = (struct message_barrier *)calloc(1, sizeof(struct message_barrier));
    GUARD_ALLOC(ret);

    ret->num_threads = num_threads;

    if (pthread_cond_init(&(ret->barrier_tripped), NULL)) {
        FATAL_ERROR("Could not initialize barrier-tripped condition variable");
    }
    if (pthread_cond_init(&(ret->message_written), NULL)) {
        FATAL_ERROR("Could not initialize message-written condition variable");
    }
    if (pthread_mutex_init(&(ret->mtx), NULL)) {
        FATAL_ERROR("Could not initialize message-barrier mutex");
    }

    return ret;
}

int message_barrier_read(struct message_barrier *barrier)
{
    int message;

    pthread_mutex_lock(&(barrier->mtx));

    while (barrier->message_present == false) {
        pthread_cond_wait(&(barrier->message_written), &(barrier->mtx));
    }
    message = barrier->message;

    pthread_mutex_unlock(&(barrier->mtx));
    return message;
}

void message_barrier_wait(struct message_barrier *barrier)
{
    bool current_generation;

    pthread_mutex_lock(&(barrier->mtx));

    current_generation = barrier->odd_even_generation;

    if (barrier->num_reached < barrier->num_threads - 1) {
        barrier->num_reached++;
        while (barrier->odd_even_generation == current_generation) {
            pthread_cond_wait(&(barrier->barrier_tripped), &(barrier->mtx));
        }
    }
    else {
        barrier->message_present = false;
        barrier->num_reached = 0;
        barrier->odd_even_generation = !(barrier->odd_even_generation);
        pthread_cond_broadcast(&(barrier->barrier_tripped));
    }

    pthread_mutex_unlock(&(barrier->mtx));
}

void message_barrier_write(struct message_barrier *barrier, int message)
{
    pthread_mutex_lock(&(barrier->mtx));

    ASSERT(barrier->message_present == false,
           "Message already written (old=%d, new=%d)", barrier->message,
           message);

    barrier->message = message;
    barrier->message_present = true;
    pthread_cond_broadcast(&(barrier->message_written));

    pthread_mutex_unlock(&(barrier->mtx));
}

void message_barrier_free(struct message_barrier *barrier)
{
    if (barrier == NULL) {
        return;
    }

    pthread_cond_destroy(&(barrier->barrier_tripped));
    pthread_cond_destroy(&(barrier->message_written));
    pthread_mutex_destroy(&(barrier->mtx));

    free(barrier);
}
