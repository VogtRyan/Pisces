/*
 * Copyright (c) 2008-2023 Ryan Vogt <rvogt.ca@gmail.com>
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

struct holdbuf {
    byte_t *buf;
    size_t stopSize;
    size_t inBuf;
};

struct holdbuf *holdbuf_alloc(size_t stopSize)
{
    struct holdbuf *ret = calloc(1, sizeof(struct holdbuf));
    ASSERT_ALLOC(ret);

    ret->buf = calloc(1, stopSize);
    ASSERT_ALLOC(ret->buf);
    ret->stopSize = stopSize;

    return ret;
}

void holdbuf_give(struct holdbuf *hb, const byte_t *bytes, size_t numBytes,
                  byte_t *output, size_t *outputBytes)
{
    size_t toFill, fromBuf, fromInput;

    /*
     * Compute how much data goes back to caller. The subtraction is safe,
     * since inBuf <= stopSize.
     */
    toFill = hb->stopSize - hb->inBuf;
    if (numBytes < toFill) {
        *outputBytes = 0;
    }
    else {
        *outputBytes = numBytes - toFill;
    }

    if (*outputBytes > 0) {
        /*
         * The amount given back is divided into how much comes from storage
         * and how much from the input.
         */
        fromBuf = (*outputBytes) < (hb->inBuf) ? (*outputBytes) : (hb->inBuf);
        fromInput = *outputBytes - fromBuf;

        /* Give the data to the caller */
        memcpy(output, hb->buf, fromBuf);
        memcpy(output + fromBuf, bytes, fromInput);

        /* Update the stored buffer */
        hb->inBuf -= fromBuf;
        memmove(hb->buf, hb->buf + fromBuf, hb->inBuf);

        /* Update the input passed to us */
        bytes += fromInput;
        numBytes -= fromInput;
    }

    /* Add data we received (and haven't given back) to our storage */
    memcpy(hb->buf + hb->inBuf, bytes, numBytes);
    hb->inBuf += numBytes;
}

int holdbuf_end(struct holdbuf *hb, byte_t *output)
{
    int errVal = 0;

    if (hb->inBuf != hb->stopSize) {
        ERROR_CODE(isErr, errVal, HOLDBUF_ERROR_INSUFFICIENT_DATA);
    }
    memcpy(output, hb->buf, hb->inBuf);
    hb->inBuf = 0;

isErr:
    return errVal;
}

void holdbuf_free_scrub(struct holdbuf *hb)
{
    if (hb != NULL) {
        if (hb->buf != NULL) {
            scrub_memory(hb->buf, hb->stopSize);
            free(hb->buf);
        }
        scrub_memory(hb, sizeof(struct holdbuf));
        free(hb);
    }
}
