/*
 * Copyright (c) 2011-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "cprng.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"

#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Set the default implementation of the random number generator used by
 * cprng_alloc_default(). The arc4random() family of functions, which is
 * the preferred source of random data, is assumed to be available unless
 * indicated at compile time.
 */
#ifndef PISCES_NO_ARC4RANDOM
#define CPRNG_DEFAULT_ALG (CPRNG_ALG_ARC4RANDOM)
#else
#define CPRNG_DEFAULT_ALG (CPRNG_ALG_DEVRANDOM)
#endif

/*
 * The device name to use if drawing random data from the /dev/ set of devices.
 * It is assumed that reads from the device will eventually succeed; it is a
 * fatal error for a read to fail.
 */
#define CPRNG_DEVICE_NAME ("/dev/random")

/*
 * This struct represents the different cryptographic pseudorandom number
 * generators that can be used.
 */
typedef enum { CPRNG_ALG_ARC4RANDOM, CPRNG_ALG_DEVRANDOM } cprng_algorithm_t;
struct cprng {
    cprng_algorithm_t type;
    int fd;
};

/*
 * Fills the buffer with random data read from random-soruce device in /dev/
 */
static void cprng_bytes_devrandom(struct cprng *rng, byte_t *bytes,
                                  size_t numBytes);

/* Annotate a variable as unused, inside a function body */
#define UNUSED(varname) (void)(varname)

/*
 * Make arc4random_buf(void *, size_t) visible even when compiling against the
 * POSIX.1-2001 standard.
 *
 * The dead-code implementation of the function is to prevent warnings not from
 * the compiler, but from IDEs that view the extern declaration as missing an
 * implementation.
 */
#ifdef _POSIX_C_SOURCE
#if _POSIX_C_SOURCE != 200112L
#error Only the POSIX.1-2001 standard is supported
#endif
#ifndef PISCES_NO_ARC4RANDOM
extern void arc4random_buf(void *buf, size_t nbytes);
#else
static void arc4random_buf(void *buf, size_t nbytes)
{
    UNUSED(buf);
    UNUSED(nbytes);
    ASSERT_NEVER_REACH("Not compiled with arc4random_buf() support");
}
#endif
#endif

struct cprng *cprng_alloc_default(void)
{
    struct cprng *ret = (struct cprng *)calloc(1, sizeof(struct cprng));
    GUARD_ALLOC(ret);

    ret->type = CPRNG_DEFAULT_ALG;
    ret->fd = -1;

    return ret;
}

void cprng_bytes(struct cprng *rng, byte_t *bytes, size_t numBytes)
{
    ASSERT(numBytes <= SSIZE_MAX, "Amount of data to read is too large");

    switch (rng->type) {
    case CPRNG_ALG_ARC4RANDOM:
        arc4random_buf(bytes, numBytes);
        break;
    case CPRNG_ALG_DEVRANDOM:
        cprng_bytes_devrandom(rng, bytes, numBytes);
        break;
    default:
        ASSERT_NEVER_REACH("Invalid CPRNG algorithm");
    }
}

void cprng_free_scrub(struct cprng *rng)
{
    if (rng != NULL) {
        if (rng->fd >= 0) {
            close(rng->fd);
        }
        scrub_memory(rng, sizeof(struct cprng));
        free(rng);
    }
}

static void cprng_bytes_devrandom(struct cprng *rng, byte_t *bytes,
                                  size_t numBytes)
{
    ssize_t res;

    if (rng->fd < 0) {
        rng->fd = open(CPRNG_DEVICE_NAME, O_RDONLY);
        if (rng->fd < 0) {
            FATAL_ERROR("Unable to open %s", CPRNG_DEVICE_NAME);
        }
    }

    while (numBytes > 0) {
        res = read(rng->fd, bytes, numBytes);
        if (res == 0) {
            FATAL_ERROR("Read from %s returned no data", CPRNG_DEVICE_NAME);
        }
        if (res < 0) {
            FATAL_ERROR("Read from %s failed", CPRNG_DEVICE_NAME);
        }
        bytes += res;
        numBytes -= (size_t)res;
    }
}
