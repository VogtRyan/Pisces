/*
 * Copyright (c) 2023-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_CRYPTO_TEST_FRAMEWORK_H_
#define PISCES_CRYPTO_TEST_FRAMEWORK_H_

#include <stdio.h>
#include <stdlib.h>

#ifndef TEST_SUCCESS_OUTPUT
#define TEST_SUCCESS_OUTPUT stdout
#endif
#ifndef TEST_FAILED_OUTPUT
#define TEST_FAILED_OUTPUT stderr
#endif

#define TEST_PREAMBLE(name)                                                   \
    static const char *TEST_NAME = (name);                                    \
    static int TEST_ASSERTIONS_FAILED = 0;                                    \
    static int TEST_ASSERTIONS_TOTAL = 0

#define TEST_ASSERT(condition)                                                \
    do {                                                                      \
        TEST_ASSERTIONS_TOTAL++;                                              \
        if (!(condition)) {                                                   \
            fprintf(TEST_FAILED_OUTPUT, "%s assertion %d failed\n",           \
                    TEST_NAME, TEST_ASSERTIONS_TOTAL);                        \
            fflush(TEST_FAILED_OUTPUT);                                       \
            TEST_ASSERTIONS_FAILED++;                                         \
        }                                                                     \
    } while (0)

#define TEST_CONCLUDE()                                                       \
    do {                                                                      \
        if (TEST_ASSERTIONS_FAILED) {                                         \
            fprintf(TEST_FAILED_OUTPUT, "%s test failed (score: %d/%d)\n",    \
                    TEST_NAME,                                                \
                    TEST_ASSERTIONS_TOTAL - TEST_ASSERTIONS_FAILED,           \
                    TEST_ASSERTIONS_TOTAL);                                   \
            fflush(TEST_FAILED_OUTPUT);                                       \
            exit(-1);                                                         \
        }                                                                     \
        else {                                                                \
            fprintf(TEST_SUCCESS_OUTPUT, "%s test passed (score: %d/%d)\n",   \
                    TEST_NAME, TEST_ASSERTIONS_TOTAL, TEST_ASSERTIONS_TOTAL); \
            fflush(TEST_SUCCESS_OUTPUT);                                      \
            exit(0);                                                          \
        }                                                                     \
    } while (0)

#endif
