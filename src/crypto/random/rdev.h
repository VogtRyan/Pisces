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

#ifndef PISCES_CRYPTO_RANDOM_RDEV_H_
#define PISCES_CRYPTO_RANDOM_RDEV_H_

#include "common/bytetype.h"

#include <stddef.h>

#ifndef RDEV_DEVICE_NAME
#define RDEV_DEVICE_NAME ("/dev/random")
#endif

/*
 * Returns a file descriptor for reading from the random device in /dev/.
 * Succeeds or the program terminates.
 */
int rdev_open(void);

/*
 * Fills the output buffer with random data from the random device in /dev/.
 * Succeeds or the program terminates, but may block for a finite time.
 */
void rdev_fill(int fd, byte *output, size_t output_len);

#endif
