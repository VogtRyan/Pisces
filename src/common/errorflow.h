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

#ifndef PISCES_COMMON_ERRORFLOW_H_
#define PISCES_COMMON_ERRORFLOW_H_

#include <stdio.h>
#include <stdlib.h>

#ifndef ERROR_OUTPUT
#define ERROR_OUTPUT stderr
#endif

/*
 * Print the given message, set the error flag to 1, and jump to the specified
 * target. If DEBUGGING is defined, also include the file and line number in
 * the output.
 */
#ifdef DEBUGGING
#define ERROR(target, flag, ...)                                              \
    do {                                                                      \
        fprintf(ERROR_OUTPUT, "Error [%s:%d]: ", __FILE__, __LINE__);         \
        fprintf(ERROR_OUTPUT, __VA_ARGS__);                                   \
        fprintf(ERROR_OUTPUT, "\n");                                          \
        fflush(ERROR_OUTPUT);                                                 \
        flag = 1;                                                             \
        goto target;                                                          \
    } while (0)
#else
#define ERROR(target, flag, ...)                                              \
    do {                                                                      \
        fprintf(ERROR_OUTPUT, "Error: ");                                     \
        fprintf(ERROR_OUTPUT, __VA_ARGS__);                                   \
        fprintf(ERROR_OUTPUT, "\n");                                          \
        fflush(ERROR_OUTPUT);                                                 \
        flag = 1;                                                             \
        goto target;                                                          \
    } while (0)
#endif

/*
 * Set the error flag to the given integer value, and jump to the specified
 * target. If DEBUGGING is defined, print a message with the file and line
 * number (otherwise, print nothing).
 */
#ifdef DEBUGGING
#define ERROR_CODE(target, flag, flagValue)                                   \
    do {                                                                      \
        fprintf(ERROR_OUTPUT, "Error code %d [%s:%d]\n", flagValue, __FILE__, \
                __LINE__);                                                    \
        fflush(ERROR_OUTPUT);                                                 \
        flag = (flagValue);                                                   \
        goto target;                                                          \
    } while (0)
#else
#define ERROR_CODE(target, flag, flagValue)                                   \
    do {                                                                      \
        flag = (flagValue);                                                   \
        goto target;                                                          \
    } while (0)
#endif

/*
 * Set the error flag to 1, and jump to the specified target. If DEBUGGING is
 * defined, print a message with the file and line number (otherwise print
 * nothing). Functionally equivalent to ERROR_CODE(target, flag, 1), though the
 * message printed is slightly different.
 */
#ifdef DEBUGGING
#define ERROR_QUIET(target, flag)                                             \
    do {                                                                      \
        fprintf(ERROR_OUTPUT, "Quiet error [%s:%d]\n", __FILE__, __LINE__);   \
        fflush(ERROR_OUTPUT);                                                 \
        flag = 1;                                                             \
        goto target;                                                          \
    } while (0)
#else
#define ERROR_QUIET(target, flag)                                             \
    do {                                                                      \
        flag = 1;                                                             \
        goto target;                                                          \
    } while (0)
#endif

/*
 * Assert that the given condition is true. Otherwise, print the given error
 * message and abort the program. If DEBUGGING is defined, additional
 * information will be printed; however, the assertion is checked in either
 * case.
 */
#ifdef DEBUGGING
#define ASSERT(condition, ...)                                                \
    do {                                                                      \
        if (!(condition)) {                                                   \
            fprintf(ERROR_OUTPUT, "Failed assertion [%s:%d]\n", __FILE__,     \
                    __LINE__);                                                \
            fprintf(ERROR_OUTPUT, __VA_ARGS__);                               \
            fprintf(ERROR_OUTPUT, "\n");                                      \
            fflush(ERROR_OUTPUT);                                             \
            abort();                                                          \
        }                                                                     \
    } while (0)
#else
#define ASSERT(condition, ...)                                                \
    do {                                                                      \
        if (!(condition)) {                                                   \
            fprintf(ERROR_OUTPUT, "Error: ");                                 \
            fprintf(ERROR_OUTPUT, __VA_ARGS__);                               \
            fprintf(ERROR_OUTPUT, "\n");                                      \
            fflush(ERROR_OUTPUT);                                             \
            abort();                                                          \
        }                                                                     \
    } while (0)
#endif

/*
 * Assert that the return from an allocation call, such as malloc() or calloc()
 * is non-NULL. If not, print an error message and abort. If DEBUGGING is
 * defined, additional information will be printed; however, the pointer is
 * checked in either case.
 */
#ifdef DEBUGGING
#define GUARD_ALLOC(ptr)                                                      \
    do {                                                                      \
        if ((ptr) == NULL) {                                                  \
            fprintf(ERROR_OUTPUT, "Memory allocation failed [%s:%d]\n",       \
                    __FILE__, __LINE__);                                      \
            fflush(ERROR_OUTPUT);                                             \
            abort();                                                          \
        }                                                                     \
    } while (0)
#else
#define GUARD_ALLOC(ptr)                                                      \
    do {                                                                      \
        if ((ptr) == NULL) {                                                  \
            fprintf(ERROR_OUTPUT, "Memory allocation failed\n");              \
            abort();                                                          \
        }                                                                     \
    } while (0)
#endif

/*
 * Print the given error message and abort the program. If DEBUGGING is
 * defined, additional information will be printed; however, the program will
 * be aborted in either case.
 */
#ifdef DEBUGGING
#define FATAL_ERROR(...)                                                      \
    do {                                                                      \
        fprintf(ERROR_OUTPUT, "Fatal error at [%s:%d]\n", __FILE__,           \
                __LINE__);                                                    \
        fprintf(ERROR_OUTPUT, __VA_ARGS__);                                   \
        fprintf(ERROR_OUTPUT, "\n");                                          \
        fflush(ERROR_OUTPUT);                                                 \
        abort();                                                              \
    } while (0)
#else
#define FATAL_ERROR(...)                                                      \
    do {                                                                      \
        fprintf(ERROR_OUTPUT, "Fatal error: ");                               \
        fprintf(ERROR_OUTPUT, __VA_ARGS__);                                   \
        fprintf(ERROR_OUTPUT, "\n");                                          \
        fflush(ERROR_OUTPUT);                                                 \
        abort();                                                              \
    } while (0)
#endif

#endif
