/*
 * Copyright (c) 2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_CRYPTO_ALGORITHMS_ARGON2_ARGON2_H_
#define PISCES_CRYPTO_ALGORITHMS_ARGON2_ARGON2_H_

#include "common/bytetype.h"

#include <stddef.h>

#define ARGON2_ERROR_PASSWORD_TOO_LONG        (-1)
#define ARGON2_ERROR_SALT_TOO_LONG            (-2)
#define ARGON2_ERROR_DERIVED_KEY_TOO_SHORT    (-3)
#define ARGON2_ERROR_DERIVED_KEY_TOO_LONG     (-4)
#define ARGON2_ERROR_SECRET_DATA_TOO_LONG     (-5)
#define ARGON2_ERROR_ASSOCIATED_DATA_TOO_LONG (-6)

#define ARGON2_MAX_THREADS_AUTO   (0)
#define ARGON2_MAX_THREADS_SINGLE (1)

typedef enum {
    ARGON2_VARIANT_D,
    ARGON2_VARIANT_I,
    ARGON2_VARIANT_ID
} argon2_variant;

struct argon2_ctx;

/*
 * Allocates memory for an Argon2 computation as specified in RFC 9106, and is
 * guaranteed to return non-NULL. Up to p_parallelism-1 worker threads will be
 * spawned. The main thread also performs computational work in this
 * implementation, meaning there will be up to p_parallelism threads working on
 * key derivation.
 *
 * If max_threads > 0, no more than max_threads-1 worker threads will
 * be spawned. Provided for convenience are the constants
 * ARGON2_MAX_THREADS_AUTO for using a full set of p_parallelism-1 worker
 * threads, and ARGON2_MAX_THREADS_SINGLE for single-threaded computation by
 * the main thread.
 */
struct argon2_ctx *argon2_alloc(argon2_variant y_variant,
                                unsigned long m_memsize_kb,
                                unsigned long p_parallelism,
                                unsigned long t_passes,
                                unsigned long max_threads);

/*
 * Derives key material using Argon2. Returns 0 on success, <0 on error (in
 * order of precedence from highest to lowest: ARGON2_ERROR_PASSWORD_TOO_LONG
 * ARGON2_ERROR_SALT_TOO_LONG, ARGON2_ERROR_DERIVED_KEY_TOO_SHORT/LONG).
 */
int argon2_derive(struct argon2_ctx *ctx, byte *derived_key,
                  size_t derived_key_len, const char *password,
                  size_t password_len, const byte *salt, size_t salt_len);

/*
 * Derives key material using Argon2. Returns 0 on success, <0 on error (in
 * order of precedence from highest to lowest: ARGON2_ERROR_PASSWORD_TOO_LONG,
 * ARGON2_ERROR_SALT_TOO_LONG, ARGON2_ERROR_DERIVED_KEY_TOO_SHORT/LONG,
 * ARGON2_ERROR_SECRET_DATA_TOO_LONG, ARGON2_ERROR_ASSOCIATED_DATA_TOO_LONG).
 */
int argon2_derive_opt(struct argon2_ctx *ctx, byte *derived_key,
                      size_t derived_key_len, const char *password,
                      size_t password_len, const byte *salt, size_t salt_len,
                      const byte *k_secret, size_t k_secret_len,
                      const byte *x_associated, size_t x_associated_len);

/*
 * Frees an Argon2 context allocated with argon2_alloc() and securely scrubs
 * memory allocated for the context. Calling with NULL is a no-op.
 */
void argon2_free_scrub(struct argon2_ctx *ctx);

#endif
