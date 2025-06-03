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

#ifndef PISCES_CRYPTO_ABSTRACT_KDF_H_
#define PISCES_CRYPTO_ABSTRACT_KDF_H_

#include "common/bytetype.h"

#include <stddef.h>

typedef enum {
    KDF_ALG_PBKDF2_HMAC_SHA3_512_16384,
    KDF_ALG_PBKDF2_HMAC_SHA1_4096,
    KDF_ALG_PBKDF2_HMAC_SHA1_1024
} kdf_algorithm;

#define KDF_ERROR_PASSWORD_TOO_LONG    (-1)
#define KDF_ERROR_SALT_TOO_LONG        (-2)
#define KDF_ERROR_DERIVED_KEY_TOO_LONG (-3)

struct kdf;

/*
 * Allocates a new cryptographic key derivation function. Must be freed with
 * kdf_free_scrub(). Guaranteed to return non-NULL.
 */
struct kdf *kdf_alloc(kdf_algorithm alg);

/*
 * Runs the key derivation function, filling the derived_key array with the
 * requested number of bytes of key material. Returns 0 on success, <0 on
 * error (KDF_ERROR_PASSWORD_TOO_LONG, KDF_ERROR_SALT_TOO_LONG, or
 * KDF_ERROR_DERIVED_KEY_TOO_LONG, from highest to lowest precedence).
 */
int kdf_derive(struct kdf *fn, byte *derived_key, size_t derived_key_len,
               const char *password, size_t password_len, const byte *salt,
               size_t salt_len);

/*
 * Returns a human-readable description of the most recent outcome of
 * kdf_derive().
 */
const char *kdf_error(const struct kdf *fn);

/*
 * Frees a cryptographic hash function allocated with kdf_alloc() and securely
 * scrubs all memory allocated for it. Calling with NULL is a no-op.
 */
void kdf_free_scrub(struct kdf *fn);

#endif
