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
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/chf.h"
#include "crypto/abstract/cipher.h"
#include "crypto/abstract/kdf.h"

#include <stdbool.h>

#define SPEC_VERSION_EARLIEST_SUPPORTED (3U)

struct spec {
    byte version;
};

struct spec *spec_alloc(byte version)
{
    struct spec *ret;

    ASSERT(spec_version_supported(version),
           "Unsupported Pisces specification (%hhu)", version);

    ret = (struct spec *)calloc(1, sizeof(struct spec));
    GUARD_ALLOC(ret);

    ret->version = version;

    return ret;
}

bool spec_version_supported(byte version)
{
    return (version >= SPEC_VERSION_EARLIEST_SUPPORTED &&
            version <= SPEC_VERSION_LATEST);
}

byte spec_version(const struct spec *ps)
{
    return ps->version;
}

struct cipher_ctx *spec_unpadded_cipher_alloc(const struct spec *ps)
{
    struct cipher_ctx *ret;

    switch (ps->version) {
    case 3:
        ret = cipher_alloc(CIPHER_ALG_AES_128_CBC);
        break;
    case 4:
        ret = cipher_alloc(CIPHER_ALG_AES_256_CBC);
        break;
    case 5:
        ret = cipher_alloc(CIPHER_ALG_AES_256_CBC);
        break;
    default:
        ASSERT_NEVER_REACH("Illegal Pisces specification version");
    }

    cipher_set_padding(ret, CIPHER_PADDING_NONE);
    return ret;
}

struct cipher_ctx *spec_padded_cipher_alloc(const struct spec *ps)
{
    struct cipher_ctx *ret;

    switch (ps->version) {
    case 3:
        ret = cipher_alloc(CIPHER_ALG_AES_128_CBC);
        break;
    case 4:
        ret = cipher_alloc(CIPHER_ALG_AES_256_CBC);
        break;
    case 5:
        ret = cipher_alloc(CIPHER_ALG_AES_256_CBC);
        break;
    default:
        ASSERT_NEVER_REACH("Illegal Pisces specification version");
    }

    cipher_set_padding(ret, CIPHER_PADDING_PKCS7);
    return ret;
}

struct chf_ctx *spec_chf_alloc(const struct spec *ps)
{
    switch (ps->version) {
    case 3:
        return chf_alloc(CHF_ALG_SHA1);
    case 4:
        return chf_alloc(CHF_ALG_SHA1);
    case 5:
        return chf_alloc(CHF_ALG_SHA3_512);
    default:
        ASSERT_NEVER_REACH("Illegal Pisces specification version");
    }
}

struct kdf *spec_kdf_alloc(const struct spec *ps)
{
    switch (ps->version) {
    case 3:
        return kdf_alloc(KDF_ALG_PBKDF2_HMAC_SHA1_C1024_S128);
    case 4:
        return kdf_alloc(KDF_ALG_PBKDF2_HMAC_SHA1_C4096_S256);
    case 5:
        return kdf_alloc(KDF_ALG_PBKDF2_HMAC_SHA3_512_C16384_S256);
    default:
        ASSERT_NEVER_REACH("Illegal Pisces specification version");
    }
}

void spec_free_scrub(struct spec *ps)
{
    if (ps == NULL) {
        return;
    }

    scrub_memory(ps, sizeof(struct spec));
    free(ps);
}
