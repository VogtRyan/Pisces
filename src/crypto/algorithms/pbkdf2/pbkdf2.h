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

#ifndef PISCES_CRYPTO_ALGORITHMS_PBKDF2_PBKDF2_H_
#define PISCES_CRYPTO_ALGORITHMS_PBKDF2_PBKDF2_H_

#include "common/bytetype.h"
#include "crypto/abstract/chf.h"

#include <stddef.h>

#define PBKDF2_ERROR_PASSWORD_TOO_LONG    (-1)
#define PBKDF2_ERROR_SALT_TOO_LONG        (-2)
#define PBKDF2_ERROR_DERIVED_KEY_TOO_LONG (-3)

/*
 * Derives key material using PBKDF2, as specified in RFC 2898.
 *
 * The underlying pseudorandom function, called "PRF" in the specification, is
 * HMAC. The HMAC operation itself uses the provided cryptographic hash
 * function, alg. The iteration count, called "c" in the specification, must be
 * positive.
 *
 * Returns 0 on success, <0 on error (in order of precedence from highest to
 * lowest: PBKDF2_ERROR_PASSWORD_TOO_LONG, PBKDF2_ERROR_SALT_TOO_LONG,
 * PBKDF2_ERROR_DERIVED_KEY_TOO_LONG).
 */
int pbkdf2_hmac(byte *derived_key, size_t derived_key_len,
                const char *password, size_t password_len, const byte *salt,
                size_t salt_len, unsigned int iteration_count,
                chf_algorithm alg);

#endif
