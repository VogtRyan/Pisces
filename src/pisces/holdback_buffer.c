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

#include "holdback_buffer.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct holdback_buffer {
    byte *buf;
    size_t holdback_size;
    size_t in_buf;
};

struct holdback_buffer *holdback_buffer_alloc(size_t holdback_size)
{
    struct holdback_buffer *ret;

    ret = calloc(1, sizeof(struct holdback_buffer));
    GUARD_ALLOC(ret);

    ret->buf = calloc(1, holdback_size);
    GUARD_ALLOC(ret->buf);

    ret->holdback_size = holdback_size;

    return ret;
}

void holdback_buffer_append(struct holdback_buffer *hb, const byte *input,
                            size_t input_len, byte *output, size_t *output_len)
{
    size_t to_fill, from_buf, from_input;

    to_fill = hb->holdback_size - hb->in_buf;
    if (input_len <= to_fill) {
        *output_len = 0;
    }
    else {
        *output_len = input_len - to_fill;
    }

    if (*output_len > 0) {
        /*
         * Data given back to the caller comes first from the holdback buffer
         * itself, then from the input buffer (FIFO order).
         */
        from_buf = MIN(*output_len, hb->in_buf);
        from_input = *output_len - from_buf;

        /*
         * Give back data from the front of the holdback buffer.
         *
         * This implementation assumes that, typically,
         * input_len >= holdback_size. So this memmove() should typically be
         * zero-length.
         */
        memcpy(output, hb->buf, from_buf);
        hb->in_buf -= from_buf;
        memmove(hb->buf, hb->buf + from_buf, hb->in_buf);

        /* Give data back from the front of the input buffer */
        memcpy(output + from_buf, input, from_input);
        input += from_input;
        input_len -= from_input;
    }

    memcpy(hb->buf + hb->in_buf, input, input_len);
    hb->in_buf += input_len;
}

int holdback_buffer_finalize(struct holdback_buffer *hb, byte *output)
{
    if (hb->in_buf != hb->holdback_size) {
        return HOLDBACK_BUFFER_ERROR_INSUFFICIENT_DATA;
    }

    memcpy(output, hb->buf, hb->in_buf);
    hb->in_buf = 0;
    return 0;
}

void holdback_buffer_free_scrub(struct holdback_buffer *hb)
{
    if (hb != NULL) {
        scrub_memory(hb->buf, hb->holdback_size);
        free(hb->buf);

        scrub_memory(hb, sizeof(struct holdback_buffer));
        free(hb);
    }
}
