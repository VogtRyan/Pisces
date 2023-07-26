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

#ifndef PISCES_PISCES_PASSWORD_H_
#define PISCES_PISCES_PASSWORD_H_

#include "common/pwlimits.h"

#include <stddef.h>

/*
 * Prompts the user to input an encryption password, then a second time to
 * confirm it, if providedPassword is NULL. The user-input password will be
 * written to the password array and its length stored in passwordLen.
 *
 * If providedPassword is non-NULL, it is treated as both the user's first
 * password input and its confirmation input, and the password and passwordLen
 * variables are updated accordingly.
 *
 * The data stored in the password array will NOT be NULL-terminated. The
 * password array must be of length at least PASSWORD_LENGTH_MAX. Returns 0 on
 * success, or -1 on error (and prints an error message).
 */
int get_encryption_password(char *password, size_t *passwordLen,
                            const char *providedPassword);

/*
 * Prompts the user to input a decryption password. Unlike with
 * get_encryption_password(), there is no second input to confirm the password.
 * Otherwise, the contract of this function is identical to that of
 * get_encryption_password().
 */
int get_decryption_password(char *password, size_t *passwordLen,
                            const char *providedPassword);

#endif
