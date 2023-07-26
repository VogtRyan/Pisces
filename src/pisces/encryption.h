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

#ifndef PISCES_PISCES_ENCRYPTION_H_
#define PISCES_PISCES_ENCRYPTION_H_

#include <stddef.h>

/*
 * Encrypts inputFile to outputFile. If either of those is NULL, standard
 * in/out will be used, respectively. The given password will be used to
 * encrypt the file. Return 0 on success, -1 on error (and prints error
 * messages).
 */
int encrypt_file(const char *inputFile, const char *outputFile,
                 const char *password, size_t passwordLen);

/*
 * Decrypts inputFile to outputFile. If either of those is NULL, standard
 * in/out will be used, respectively. The given password will be used to
 * decrypt the file. Returns 0 on success, -1 on error (and prints error
 * messages).
 */
int decrypt_file(const char *inputFile, const char *outputFile,
                 const char *password, size_t passwordLen);

#endif
