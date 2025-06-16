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

#include "kdf.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/chf.h"
#include "crypto/algorithms/pbkdf2/pbkdf2.h"

#include <stddef.h>
#include <stdlib.h>

struct kdf {
    chf_algorithm chf_alg;
    unsigned int iteration_count;
    int errcode;
};

struct kdf *kdf_alloc(kdf_algorithm alg)
{
    struct kdf *ret;

    ret = (struct kdf *)calloc(1, sizeof(struct kdf));
    GUARD_ALLOC(ret);

    switch (alg) {
    case KDF_ALG_PBKDF2_HMAC_SHA3_512_16384:
        ret->iteration_count = 16384;
        ret->chf_alg = CHF_ALG_SHA3_512;
        break;
    case KDF_ALG_PBKDF2_HMAC_SHA1_4096:
        ret->iteration_count = 4096;
        ret->chf_alg = CHF_ALG_SHA1;
        break;
    case KDF_ALG_PBKDF2_HMAC_SHA1_1024:
        ret->iteration_count = 1024;
        ret->chf_alg = CHF_ALG_SHA1;
        break;
    default:
        ASSERT_NEVER_REACH("Invalid KDF algorithm");
    }

    return ret;
}

int kdf_derive(struct kdf *fn, byte *derived_key, size_t derived_key_len,
               const char *password, size_t password_len, const byte *salt,
               size_t salt_len)
{
    int pbkdf2_ret;

    pbkdf2_ret =
        pbkdf2_hmac(derived_key, derived_key_len, password, password_len, salt,
                    salt_len, fn->iteration_count, fn->chf_alg);

    switch (pbkdf2_ret) {
    case 0:
        fn->errcode = 0;
        break;
    case PBKDF2_ERROR_DERIVED_KEY_TOO_LONG:
        fn->errcode = KDF_ERROR_DERIVED_KEY_TOO_LONG;
        break;
    case PBKDF2_ERROR_PASSWORD_TOO_LONG:
        fn->errcode = KDF_ERROR_PASSWORD_TOO_LONG;
        break;
    case PBKDF2_ERROR_SALT_TOO_LONG:
        fn->errcode = KDF_ERROR_SALT_TOO_LONG;
        break;
    default:
        ASSERT_NEVER_REACH("Unknown PBKDF2 error return");
    }

    return fn->errcode;
}

const char *kdf_error(const struct kdf *fn)
{
    switch (fn->errcode) {
    case 0:
        return "No error with KDF";
    case KDF_ERROR_DERIVED_KEY_TOO_LONG:
        return "KDF derived key too long";
    case KDF_ERROR_PASSWORD_TOO_LONG:
        return "KDF password too long";
    case KDF_ERROR_SALT_TOO_LONG:
        return "KDF salt too long";
    default:
        ASSERT_NEVER_REACH("Invalid KDF error code");
    }
}

void kdf_free_scrub(struct kdf *fn)
{
    if (fn != NULL) {
        scrub_memory(fn, sizeof(struct kdf));
        free(fn);
    }
}
