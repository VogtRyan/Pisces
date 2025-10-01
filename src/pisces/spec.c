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

#include "spec.h"

#include "common/bytetype.h"
#include "crypto/abstract/chf.h"
#include "crypto/abstract/cipher.h"
#include "crypto/abstract/kdf.h"

int spec_init(struct spec *ps, unsigned int version)
{
    switch (version) {
    case 3:
        ps->chf_alg = CHF_ALG_SHA1;
        ps->cipher_alg = CIPHER_ALG_AES_128_CBC;
        ps->kdf_alg = KDF_ALG_PBKDF2_HMAC_SHA1_C1024_S128;
        break;
    case 4:
        ps->chf_alg = CHF_ALG_SHA1;
        ps->cipher_alg = CIPHER_ALG_AES_256_CBC;
        ps->kdf_alg = KDF_ALG_PBKDF2_HMAC_SHA1_C4096_S256;
        break;
    case 5:
        ps->chf_alg = CHF_ALG_SHA3_512;
        ps->cipher_alg = CIPHER_ALG_AES_256_CBC;
        ps->kdf_alg = KDF_ALG_PBKDF2_HMAC_SHA3_512_C16384_S256;
        break;
    default:
        return -1;
    }

    ps->version = version;

    return 0;
}
