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

#include "version.h"

#include "common/errorflow.h"
#include "crypto/abstract/chf.h"
#include "crypto/abstract/cipher.h"
#include "crypto/abstract/kdf.h"

static int pisces_version = PISCES_VERSION_NEWEST;

int pisces_set_version(int version)
{
    if (version < PISCES_VERSION_EARLIEST_SUPPORTED ||
        version > PISCES_VERSION_NEWEST) {
        return -1;
    }
    pisces_version = version;
    return 0;
}

int pisces_get_version(void)
{
    return pisces_version;
}

struct cipher_ctx *pisces_unpadded_cipher_alloc(void)
{
    switch (pisces_version) {
    case 3:
        return cipher_alloc(CIPHER_ALG_AES_128_CBC_NOPAD);
    case 4:
        return cipher_alloc(CIPHER_ALG_AES_256_CBC_NOPAD);
    case 5:
        return cipher_alloc(CIPHER_ALG_AES_256_CBC_NOPAD);
    default:
        ASSERT_NEVER_REACH("Illegal Pisces version");
    }
}

struct cipher_ctx *pisces_padded_cipher_alloc(void)
{
    switch (pisces_version) {
    case 3:
        return cipher_alloc(CIPHER_ALG_AES_128_CBC_PKCS7PAD);
    case 4:
        return cipher_alloc(CIPHER_ALG_AES_256_CBC_PKCS7PAD);
    case 5:
        return cipher_alloc(CIPHER_ALG_AES_256_CBC_PKCS7PAD);
    default:
        ASSERT_NEVER_REACH("Illegal Pisces version");
    }
}

struct chf_ctx *pisces_chf_alloc(void)
{
    switch (pisces_version) {
    case 3:
        return chf_alloc(CHF_ALG_SHA1);
    case 4:
        return chf_alloc(CHF_ALG_SHA1);
    case 5:
        return chf_alloc(CHF_ALG_SHA3_512);
    default:
        ASSERT_NEVER_REACH("Illegal Pisces version");
    }
}

struct kdf *pisces_kdf_alloc(void)
{
    switch (pisces_version) {
    case 3:
        return kdf_alloc(KDF_ALG_PBKDF2_HMAC_SHA1_1024);
    case 4:
        return kdf_alloc(KDF_ALG_PBKDF2_HMAC_SHA1_4096);
    case 5:
        return kdf_alloc(KDF_ALG_PBKDF2_HMAC_SHA3_512_16384);
    default:
        ASSERT_NEVER_REACH("Illegal Pisces version");
    }
}
