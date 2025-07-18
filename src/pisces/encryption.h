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

#ifndef PISCES_PISCES_ENCRYPTION_H_
#define PISCES_PISCES_ENCRYPTION_H_

#include <stddef.h>

/*
 * Encrypts and decrypts files. If input_file or output_file is NULL, stdin and
 * stdout will be used, respectively. Returns 0 on success, <0 on error and
 * prints error messages.
 */

int encrypt_file(const char *input_file, const char *output_file,
                 const char *password, size_t password_len);

int decrypt_file(const char *input_file, const char *output_file,
                 const char *password, size_t password_len);

#endif
