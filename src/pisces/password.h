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

#include "common/bytetype.h"
#include "common/config.h"

#include <stddef.h>

/*
 * Prompts the user for a password on the terminal. For encryption, the user is
 * also asked to confirm their password.
 *
 * The input on the terminal cannot contain any NULL characters ('\0'). It will
 * be terminated either by a newline ('\n') or EOF on the terminal.
 *
 * Returns 0 on success, <0 on error. The contents of the password buffer and
 * the value of *password_len are modified only if the function succeeds.
 * Prints error messages.
 */
int password_prompt_encryption(byte *password, size_t *password_len);
int password_prompt_decryption(byte *password, size_t *password_len);

/*
 * Copies a provided password into the password array.
 *
 * The provided password must be NULL-terminated and no longer than
 * PASSWORD_LENGTH_MAX characters (not including the NULL-terminator). It
 * cannot contain any newline characters ('\n').
 *
 * Returns 0 on success, <0 on error. The contents of the password buffer and
 * the value of *password_len are modified only if the function succeeds.
 * Prints error messages.
 */
int password_copy(byte *password, size_t *password_len,
                  const char *provided_password);

#endif
