/*
 * Copyright (c) 2008-2024 Ryan Vogt <rvogt.ca@gmail.com>
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

/*
 * The error values that can be returned by pbkdf2_hmac(). If multiple error
 * conditions are true, the password being too long has the highest precedence,
 * then the salt being too long, and finally the derived key being too long.
 */
#define PBKDF2_ERROR_PASSWORD_TOO_LONG    (-1)
#define PBKDF2_ERROR_SALT_TOO_LONG        (-2)
#define PBKDF2_ERROR_DERIVED_KEY_TOO_LONG (-3)

/*
 * Runs the PBKDF2 password-based key derivation function, as defined in RFC
 * 2898. Fills the derivedKey array with the requested number of bytes of key
 * material, derived from the given password and salt.
 *
 * The underlying pseudorandom function, called "PRF" in the PBKDF2
 * specification, is HMAC. The HMAC operation itself uses the provided
 * cryptographic hash function, alg.
 *
 * The iteration count of the algorithm, a positive integer called "c" in the
 * PBKDF2 specification, dictates the cost of producing key material. A higher
 * iteration count leads to a higher cost, and thus greater resistance to
 * attacks.
 *
 * This function returns 0 on success or a negative value on an error,
 * specifically: PBKDF2_ERROR_PASSWORD_TOO_LONG, PBKDF2_ERROR_SALT_TOO_LONG, or
 * PBKDF2_ERROR_DERIVED_KEY_TOO_LONG, with precedence in that order.
 *
 * It is a fatal error for the iterationCount to be zero, or for alg to be an
 * unsupported cryptographic hash function algorithm.
 */
int pbkdf2_hmac(byte_t *derivedKey, size_t derivedKeyLen, const char *password,
                size_t passwordLen, const byte_t *salt, size_t saltLen,
                unsigned int iterationCount, chf_algorithm_t alg);

#endif
