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

#define KDF_MAX_SALT_SIZE (32)

#define KDF_ERROR_PASSWORD_TOO_LONG     (-1)
#define KDF_ERROR_DERIVED_KEY_TOO_SHORT (-2)
#define KDF_ERROR_DERIVED_KEY_TOO_LONG  (-3)

typedef enum {
    KDF_ALG_ARGON2_ID_M6291456_P4_T1_S128,
    KDF_ALG_PBKDF2_HMAC_SHA3_512_C16384_S256,
    KDF_ALG_PBKDF2_HMAC_SHA1_C4096_S256,
    KDF_ALG_PBKDF2_HMAC_SHA1_C1024_S128
} kdf_algorithm;

struct kdf;

/*
 * Allocates a new cryptographic key derivation function. Must be freed with
 * kdf_free_scrub(). Guaranteed to return non-NULL.
 */
struct kdf *kdf_alloc(kdf_algorithm alg);

/*
 * Computes a derived key. Returns 0 on success, <0 on error (in order of
 * precedence from highest to lowest: KDF_ERROR_PASSWORD_TOO_LONG,
 * KDF_ERROR_DERIVED_KEY_TOO_LONG/SHORT).
 */
int kdf_derive(struct kdf *fn, byte *derived_key, size_t derived_key_len,
               const byte *password, size_t password_len, const byte *salt);

/*
 * Returns the size, in bytes, of the salt to be passed to kdf_derive().
 * Guaranteed to be no larger than KDF_MAX_SALT_SIZE.
 */
size_t kdf_salt_size(const struct kdf *fn);
size_t kdf_alg_salt_size(kdf_algorithm alg);

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
