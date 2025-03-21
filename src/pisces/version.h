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

#ifndef PISCES_PISCES_VERSION_H_
#define PISCES_PISCES_VERSION_H_

#include "crypto/abstract/chf.h"
#include "crypto/abstract/cipher.h"
#include "crypto/abstract/kdf.h"

/*
 * Pisces version information: the current version, and the earliest
 * version supported by this implementation.
 */
#define PISCES_VERSION_NEWEST             (5)
#define PISCES_VERSION_EARLIEST_SUPPORTED (3)

/*
 * Set the version of Pisces being used to the specified version. Returns 0 on
 * success, -1 if the provided version is unsupported.
 */
int pisces_set_version(int version);

/*
 * Gets the version of Pisces that is currently in use.
 */
int pisces_get_version(void);

/*
 * Gets the cipher used by this version of Pisces to encrypt the header.
 */
struct cipher_ctx *pisces_unpadded_cipher_alloc(void);

/*
 * Gets the cipher used by this version of Pisces to encrypt the file body.
 */
struct cipher_ctx *pisces_padded_cipher_alloc(void);

/*
 * Gets the cryptographic hash function used by this version of Pisces.
 */
struct chf_ctx *pisces_chf_alloc(void);

/*
 * Gets the key derivation function used by this version of Pisces.
 */
struct kdf *pisces_kdf_alloc(void);

#endif
