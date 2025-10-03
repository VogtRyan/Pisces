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

#include "crypto/abstract/chf.h"
#include "crypto/abstract/cipher.h"
#include "crypto/abstract/kdf.h"

struct spec {
    unsigned int version;
    chf_algorithm chf_alg;
    cipher_algorithm cipher_alg;
    kdf_algorithm kdf_alg;
};

#define SPEC_VERSION_LATEST (5U)

/*
 * Sets the algorithms in the Pisces specification to match those used by the
 * given version of Pisces. Returns 0 on success, or -1 if the Pisces version
 * is not supported by this implementation.
 */
int spec_init(struct spec *ps, unsigned int version);

#endif
