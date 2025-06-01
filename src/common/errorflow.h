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
 * - User-level errors (e.g., incorrect inputs): ERROR*
 * - System-level errors (e.g., out of memory): FATAL* and GUARD*
 * - Programming errors (e.g., should not reach): ASSERT*
 */

#ifndef DEBUGGING
#define ERROR(target, flag, ...)                                              \
    do {                                                                      \
        flag = -1;                                                            \
        fprintf(ERROR_OUTPUT, "Error: ");                                     \
        fprintf(ERROR_OUTPUT, __VA_ARGS__);                                   \
        fprintf(ERROR_OUTPUT, "\n");                                          \
        fflush(ERROR_OUTPUT);                                                 \
        goto target;                                                          \
    } while (0)
#else
#define ERROR(target, flag, ...)                                              \
    do {                                                                      \
        flag = -1;                                                            \
        fprintf(ERROR_OUTPUT, "Error [%s:%d]: ", __FILE__, __LINE__);         \
        fprintf(ERROR_OUTPUT, __VA_ARGS__);                                   \
        fprintf(ERROR_OUTPUT, "\n");                                          \
        fflush(ERROR_OUTPUT);                                                 \
        goto target;                                                          \
    } while (0)
#endif

#ifndef DEBUGGING
#define ERROR_QUIET(target, flag)                                             \
    do {                                                                      \
        flag = -1;                                                            \
        goto target;                                                          \
    } while (0)
#else
#define ERROR_QUIET(target, flag)                                             \
    do {                                                                      \
        flag = -1;                                                            \
        fprintf(ERROR_OUTPUT, "Error [%s:%d, quiet]\n", __FILE__, __LINE__);  \
        fflush(ERROR_OUTPUT);                                                 \
        goto target;                                                          \
    } while (0)
#endif

#ifndef DEBUGGING
#define ERROR_CODE(target, flag, code)                                        \
    do {                                                                      \
        flag = (code);                                                        \
        goto target;                                                          \
    } while (0)
#else
#define ERROR_CODE(target, flag, code)                                        \
    do {                                                                      \
        flag = (code);                                                        \
        fprintf(ERROR_OUTPUT, "Error [%s:%d, code %d]\n", __FILE__, __LINE__, \
                flag);                                                        \
        fflush(ERROR_OUTPUT);                                                 \
        goto target;                                                          \
    } while (0)
#endif

#ifndef DEBUGGING
#define FATAL_ERROR(...)                                                      \
    do {                                                                      \
        fprintf(ERROR_OUTPUT, "Fatal error: ");                               \
        fprintf(ERROR_OUTPUT, __VA_ARGS__);                                   \
        fprintf(ERROR_OUTPUT, "\n");                                          \
        fflush(ERROR_OUTPUT);                                                 \
        exit(EXIT_FAILURE);                                                   \
    } while (0)
#else
#define FATAL_ERROR(...)                                                      \
    do {                                                                      \
        fprintf(ERROR_OUTPUT, "Fatal error [%s:%d]: ", __FILE__, __LINE__);   \
        fprintf(ERROR_OUTPUT, __VA_ARGS__);                                   \
        fprintf(ERROR_OUTPUT, "\n");                                          \
        fflush(ERROR_OUTPUT);                                                 \
        exit(EXIT_FAILURE);                                                   \
    } while (0)
#endif

#ifndef DEBUGGING
#define GUARD_ALLOC(ptr)                                                      \
    do {                                                                      \
        if ((ptr) == NULL) {                                                  \
            fprintf(ERROR_OUTPUT,                                             \
                    "Fatal error: Memory allocation failure\n");              \
            fflush(ERROR_OUTPUT);                                             \
            exit(EXIT_FAILURE);                                               \
        }                                                                     \
    } while (0)
#else
#define GUARD_ALLOC(ptr)                                                      \
    do {                                                                      \
        if ((ptr) == NULL) {                                                  \
            fprintf(ERROR_OUTPUT,                                             \
                    "Fatal error [%s:%d]: Memory allocation failure\n",       \
                    __FILE__, __LINE__);                                      \
            fflush(ERROR_OUTPUT);                                             \
            exit(EXIT_FAILURE);                                               \
        }                                                                     \
    } while (0)
#endif

#define ASSERT(condition, ...)                                                \
    do {                                                                      \
        if (!(condition)) {                                                   \
            fprintf(ERROR_OUTPUT, "Failed assertion [%s:%d, %s]: ", __FILE__, \
                    __LINE__, #condition);                                    \
            fprintf(ERROR_OUTPUT, __VA_ARGS__);                               \
            fprintf(ERROR_OUTPUT, "\n");                                      \
            fflush(ERROR_OUTPUT);                                             \
            abort();                                                          \
        }                                                                     \
    } while (0)

#define ASSERT_NEVER_REACH(...)                                               \
    do {                                                                      \
        fprintf(ERROR_OUTPUT,                                                 \
                "Failed assertion [%s:%d, never reach]: ", __FILE__,          \
                __LINE__);                                                    \
        fprintf(ERROR_OUTPUT, __VA_ARGS__);                                   \
        fprintf(ERROR_OUTPUT, "\n");                                          \
        fflush(ERROR_OUTPUT);                                                 \
        abort();                                                              \
    } while (0)

#endif
