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

#include "rdev.h"

#include "common/bytetype.h"
#include "common/errorflow.h"

#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

int rdev_open(void)
{
    int fd;

    fd = open(RDEV_DEVICE_NAME, O_RDONLY);
    if (fd < 0) {
        FATAL_ERROR("Unable to open %s", RDEV_DEVICE_NAME);
    }
    return fd;
}

void rdev_fill(int fd, byte *output, size_t output_len)
{
    ssize_t res;

    ASSERT(fd >= 0, "Invalid file descriptor for %s", RDEV_DEVICE_NAME);

    while (output_len > 0) {
        res = read(fd, output, output_len);
        if (res == 0) {
            FATAL_ERROR("Read from %s returned no data", RDEV_DEVICE_NAME);
        }
        if (res < 0) {
            FATAL_ERROR("Read from %s failed", RDEV_DEVICE_NAME);
        }
        output += res;
        output_len -= (size_t)res;
    }
}
