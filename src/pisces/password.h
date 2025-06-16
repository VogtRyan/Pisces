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
 * These functions fill a password buffer that must be at least
 * PASSWORD_LENGTH_MAX bytes long. Its contents will NOT be NULL-terminated.
 *
 * These functions guarantee that the caller's memory (the buffer and the size
 * variable) will be modified only if the function succeeds.
 */

/*
 * Prompts the user for a password on the terminal. For encryption, the user is
 * also asked to confirm their password. Returns 0 on success, <0 if no valid
 * password is provided and prints error messages.
 */
int password_prompt_encryption(char *password, size_t *password_len);
int password_prompt_decryption(char *password, size_t *password_len);

/*
 * Copies a provided password from another source into the password array.
 * Returns 0 on success, <0 if the password is not valid and prints error
 * messages.
 */
int password_copy(char *password, size_t *password_len,
                  const char *provided_password);

#endif
