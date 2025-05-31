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

#ifndef PISCES_PISCES_PASSWORD_H_
#define PISCES_PISCES_PASSWORD_H_

#include "common/config.h"

#include <stddef.h>

/*
 * Prompts the user to input a password (and, for encryption, to confirm it).
 * The password array must be at least PASSWORD_LENGTH_MAX long. Its contents
 * will NOT be NULL-terminated.
 *
 * If providedPassword is non-NULL, it is treated as the user's input (and
 * confirmation). It must be NULL-terminated.
 *
 * Returns 0 on success, <0 on error, prints error messages.
 */
int get_encryption_password(char *password, size_t *passwordLen,
                            const char *providedPassword);
int get_decryption_password(char *password, size_t *passwordLen,
                            const char *providedPassword);

#endif
