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

#include "iowrap.h"

#include "common/errorflow.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

int open_input_file(const char *inputFile)
{
    int inFile = -1;
    int errVal = 0;

    if (inputFile == NULL) {
        inFile = STDIN_FILENO;
    }
    else {
        inFile = open(inputFile, O_RDONLY);
        if (inFile == -1) {
            ERROR_QUIET(isErr, errVal);
        }
    }

isErr:
    return errVal ? -1 : inFile;
}

int open_output_file(const char *outputFile)
{
    int outFile = -1;
    int errVal = 0;

    if (outputFile == NULL) {
        outFile = STDOUT_FILENO;
    }
    else {
        outFile =
            open(outputFile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        if (outFile == -1) {
            ERROR_QUIET(isErr, errVal);
        }
    }

isErr:
    return errVal ? -1 : outFile;
}

int read_exactly(int fd, byte_t *buf, size_t nBytes)
{
    size_t numRead = 0;
    int errVal = 0;

    if (read_up_to(fd, buf, nBytes, &numRead)) {
        ERROR_QUIET(isErr, errVal);
    }
    if (numRead != nBytes) {
        ERROR_QUIET(isErr, errVal);
    }

isErr:
    return errVal ? -1 : 0;
}

int read_up_to(int fd, byte_t *buf, size_t nBytes, size_t *numRead)
{
    ssize_t res;
    int errVal = 0;

    *numRead = 0;
    while (nBytes > 0) {
        res = read(fd, buf, nBytes);
        if (res == 0) {
            break;
        }
        if (res < 0) {
            ERROR_QUIET(isErr, errVal);
        }
        buf += res;
        nBytes -= (size_t)res;
        *numRead += (size_t)res;
    }

isErr:
    return errVal ? -1 : 0;
}

int write_exactly(int fd, const byte_t *buf, size_t nBytes)
{
    ssize_t res;
    int errVal = 0;

    while (nBytes > 0) {
        res = write(fd, buf, nBytes);
        if (res < 0) {
            ERROR_QUIET(isErr, errVal);
        }
        buf += res;
        nBytes -= (size_t)res;
    }

isErr:
    return errVal ? -1 : 0;
}
