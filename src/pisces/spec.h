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

#ifndef PISCES_PISCES_SPEC_H_
#define PISCES_PISCES_SPEC_H_

#include "common/bytetype.h"
#include "crypto/abstract/chf.h"
#include "crypto/abstract/cipher.h"
#include "crypto/abstract/kdf.h"

#include <stdbool.h>

struct spec;

#define SPEC_VERSION_LATEST (5U)

/*
 * Allocates a Pisces file format specification, which must use a supported
 * file version. Guaranteed to return non-NULL.
 */
struct spec *spec_alloc(byte version);
bool spec_version_supported(byte version);

/*
 * Guaranteed to return a value greater than 0 and no greater than
 * SPEC_VERSION_LATEST.
 */
byte spec_version(const struct spec *ps);

/*
 * Allocates a cipher, hash function, or KDF used by this Pisces file format
 * specification version. Can be called repeatedly.
 */
struct cipher_ctx *spec_unpadded_cipher_alloc(const struct spec *ps);
struct cipher_ctx *spec_padded_cipher_alloc(const struct spec *ps);
struct chf_ctx *spec_chf_alloc(const struct spec *ps);
struct kdf *spec_kdf_alloc(const struct spec *ps);

/*
 * Frees a Pisces file format specification allocated with spec_alloc() and
 * securely scrubs its memory. Calling with NULL is a no-op.
 */
void spec_free_scrub(struct spec *ps);

#endif
