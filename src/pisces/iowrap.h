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

#ifndef PISCES_PISCES_IOWRAP_H_
#define PISCES_PISCES_IOWRAP_H_

#include "common/bytetype.h"

#include <stddef.h>

/*
 * Use NULL for stdin / stdout. Opening the output file creates it if necessary
 * and truncates it. Returns a file descriptor >= 0 on success, -1 on error.
 */
int open_input_file(const char *input_file);
int open_output_file(const char *output_file);

/*
 * Reads and writes, looping on attempts to allowing for safe reading from
 * pipes. Returns 0 on success, -1 on error.
 */
int read_exactly(int fd, byte *buf, size_t nbytes);
int read_up_to(int fd, byte *buf, size_t nbytes, size_t *num_read);
int write_exactly(int fd, const byte *buf, size_t nbytes);

#endif
