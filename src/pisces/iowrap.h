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
 * Returns a file descriptor for the given file, opened for input. If inputFile
 * is NULL, it returns the file descriptor for standard in. Returns -1 on
 * error.
 */
int open_input_file(const char *inputFile);

/*
 * Returns a file descriptor for the given file, opened for output (the file
 * will be created and truncated, if necessary). If outputFile is NULL, it
 * returns the file descriptor for standard out. Returns -1 on error.
 */
int open_output_file(const char *outputFile);

/*
 * Reads exactly the given number of bytes from the given file descriptor.
 * Loops on attempts, allowing for safe reading from pipes. Returns 0 on
 * success, -1 on error.
 */
int read_exactly(int fd, byte *buf, size_t nBytes);

/*
 * Reads up to the given number of bytes from the given file descriptor. Loops
 * on attempts, allowing for safe reading from pipes. Return 0 on success and
 * set numRead to be the number of bytes read, or return -1 on error.
 */
int read_up_to(int fd, byte *buf, size_t nBytes, size_t *numRead);

/*
 * Writes exactly the given number of bytes to the given file descriptor. Loops
 * on attempts, allowing for safe writing to pipes. Return 0 on success, -1 on
 * error.
 */
int write_exactly(int fd, const byte *buf, size_t nBytes);

#endif
