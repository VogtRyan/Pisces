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

#include "holdbuf.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"

#include <stddef.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct holdbuf {
    byte *buf;
    size_t stop_size;
    size_t in_buf;
};

struct holdbuf *holdbuf_alloc(size_t stop_size)
{
    struct holdbuf *ret;

    ret = calloc(1, sizeof(struct holdbuf));
    GUARD_ALLOC(ret);

    ret->buf = calloc(1, stop_size);
    GUARD_ALLOC(ret->buf);
    ret->stop_size = stop_size;

    return ret;
}

void holdbuf_give(struct holdbuf *hb, const byte *input, size_t input_len,
                  byte *output, size_t *output_len)
{
    size_t to_fill, from_buf, from_input;

    /*
     * Compute how much data goes back to caller. The subtraction is safe,
     * since in_buf <= stop_size.
     */
    to_fill = hb->stop_size - hb->in_buf;
    if (input_len < to_fill) {
        *output_len = 0;
    }
    else {
        *output_len = input_len - to_fill;
    }

    if (*output_len > 0) {
        /*
         * Data given back to the caller comes first from the holdbuf's
         * internal buffer, then from the input buffer (FIFO order).
         */
        from_buf = MIN(*output_len, hb->in_buf);
        from_input = *output_len - from_buf;

        /* Give the data to the caller, potentially from both sources */
        memcpy(output, hb->buf, from_buf);
        memcpy(output + from_buf, input, from_input);

        /*
         * Delete data given back from the front of the holdbuf's internal
         * buffer.
         */
        hb->in_buf -= from_buf;
        memmove(hb->buf, hb->buf + from_buf, hb->in_buf);

        /* Skip data in the input that was just given back */
        input += from_input;
        input_len -= from_input;
    }

    /* Add data we haven't given back to the holdbuf's internal storage */
    memcpy(hb->buf + hb->in_buf, input, input_len);
    hb->in_buf += input_len;
}

int holdbuf_end(struct holdbuf *hb, byte *output)
{
    if (hb->in_buf != hb->stop_size) {
        return HOLDBUF_ERROR_INSUFFICIENT_DATA;
    }

    memcpy(output, hb->buf, hb->in_buf);
    hb->in_buf = 0;
    return 0;
}

void holdbuf_free_scrub(struct holdbuf *hb)
{
    if (hb != NULL) {
        if (hb->buf != NULL) {
            scrub_memory(hb->buf, hb->stop_size);
            free(hb->buf);
        }
        scrub_memory(hb, sizeof(struct holdbuf));
        free(hb);
    }
}
