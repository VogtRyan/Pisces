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

#include "iowrap.h"

#include "common/errorflow.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

int open_input_file(const char *input_file)
{
    if (input_file == NULL) {
        return STDIN_FILENO;
    }
    return open(input_file, O_RDONLY);
}

int open_output_file(const char *output_file)
{
    if (output_file == NULL) {
        return STDOUT_FILENO;
    }
    return open(output_file, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
}

int read_exactly(int fd, byte *buf, size_t nbytes)
{
    size_t num_read = 0;

    if (read_up_to(fd, buf, nbytes, &num_read)) {
        return -1;
    }
    if (num_read != nbytes) {
        return -1;
    }

    return 0;
}

int read_up_to(int fd, byte *buf, size_t nbytes, size_t *num_read)
{
    ssize_t res;

    *num_read = 0;
    while (nbytes > 0) {
        res = read(fd, buf, nbytes);
        if (res == 0) {
            break;
        }
        if (res < 0) {
            return -1;
        }
        buf += res;
        nbytes -= (size_t)res;
        *num_read += (size_t)res;
    }

    return 0;
}

int write_exactly(int fd, const byte *buf, size_t nbytes)
{
    ssize_t res;

    while (nbytes > 0) {
        res = write(fd, buf, nbytes);
        if (res < 0) {
            return -1;
        }
        buf += res;
        nbytes -= (size_t)res;
    }

    return 0;
}
