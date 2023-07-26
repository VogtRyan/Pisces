/*
 * Copyright (c) 2008-2023 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "kdf.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/chf.h"
#include "crypto/algorithms/pbkdf2/pbkdf2.h"

#include <stddef.h>
#include <stdlib.h>

struct kdf {
    unsigned int iterationCount;
    chf_algorithm_t chfAlg;
    int errorCode;
};

struct kdf *kdf_alloc(kdf_algorithm_t alg)
{
    struct kdf *ret = (struct kdf *)calloc(1, sizeof(struct kdf));
    ASSERT_ALLOC(ret);

    switch (alg) {
    case KDF_ALG_PBKDF2_HMAC_SHA3_512_16384:
        ret->iterationCount = 16384;
        ret->chfAlg = CHF_ALG_SHA3_512;
        break;
    case KDF_ALG_PBKDF2_HMAC_SHA1_4096:
        ret->iterationCount = 4096;
        ret->chfAlg = CHF_ALG_SHA1;
        break;
    case KDF_ALG_PBKDF2_HMAC_SHA1_1024:
        ret->iterationCount = 1024;
        ret->chfAlg = CHF_ALG_SHA1;
        break;
    default:
        FATAL_ERROR("Invalid KDF algorithm");
    }

    return ret;
}

int kdf_derive(struct kdf *fn, byte_t *derivedKey, size_t derivedKeyLen,
               const char *password, size_t passwordLen, const byte_t *salt,
               size_t saltLen)
{
    int pbkdf2Ret =
        pbkdf2_hmac(derivedKey, derivedKeyLen, password, passwordLen, salt,
                    saltLen, fn->iterationCount, fn->chfAlg);
    int ret = 0;

    switch (pbkdf2Ret) {
    case 0:
        ret = 0;
        break;
    case PBKDF2_ERROR_DERIVED_KEY_TOO_LONG:
        ret = KDF_ERROR_DERIVED_KEY_TOO_LONG;
        break;
    case PBKDF2_ERROR_PASSWORD_TOO_LONG:
        ret = KDF_ERROR_PASSWORD_TOO_LONG;
        break;
    case PBKDF2_ERROR_SALT_TOO_LONG:
        ret = KDF_ERROR_SALT_TOO_LONG;
        break;
    default:
        FATAL_ERROR("Unknown PBKDF2 error return");
    }

    fn->errorCode = ret;
    return ret;
}

const char *kdf_error(const struct kdf *fn)
{
    switch (fn->errorCode) {
    case 0:
        return "No error with KDF";
    case KDF_ERROR_DERIVED_KEY_TOO_LONG:
        return "KDF derived key too long";
    case KDF_ERROR_PASSWORD_TOO_LONG:
        return "KDF password too long";
    case KDF_ERROR_SALT_TOO_LONG:
        return "KDF salt too long";
    default:
        FATAL_ERROR("Invalid KDF error code");
    }
}

void kdf_free_scrub(struct kdf *fn)
{
    if (fn != NULL) {
        scrub_memory(fn, sizeof(struct kdf));
        free(fn);
    }
}
