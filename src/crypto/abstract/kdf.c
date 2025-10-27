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
#include "crypto/algorithms/argon2/argon2.h"
#include "crypto/algorithms/pbkdf2/pbkdf2.h"

#include <stddef.h>
#include <stdlib.h>

#ifdef PISCES_NO_MULTITHREAD
#define KDF_ARGON2_MAX_THREADS (ARGON2_MAX_THREADS_SINGLE)
#else
#define KDF_ARGON2_MAX_THREADS (ARGON2_MAX_THREADS_AUTO)
#endif

struct kdf {
    kdf_algorithm alg;
    struct argon2_ctx *a2ctx;
    int errcode;
};

static int run_argon2(byte *derived_key, size_t derived_key_len,
                      const byte *password, size_t password_len,
                      const byte *salt, size_t salt_len,
                      struct argon2_ctx *a2ctx);
static int run_pbkdf2(byte *derived_key, size_t derived_key_len,
                      const byte *password, size_t password_len,
                      const byte *salt, size_t salt_len,
                      unsigned int iteration_count, chf_algorithm chf_alg);

struct kdf *kdf_alloc(kdf_algorithm alg)
{
    struct kdf *ret;

    ret = (struct kdf *)calloc(1, sizeof(struct kdf));
    GUARD_ALLOC(ret);

    ret->alg = alg;

    switch (alg) {
    case KDF_ALG_ARGON2_ID_M6291456_P4_T1_S128:
        /* RFC 9106, section 4, hard-drive encryption recommendation */
        ret->a2ctx = argon2_alloc(ARGON2_VARIANT_ID, 6291456, 4, 1,
                                  KDF_ARGON2_MAX_THREADS);
        break;
    case KDF_ALG_PBKDF2_HMAC_SHA3_512_C16384_S256:
    case KDF_ALG_PBKDF2_HMAC_SHA1_C4096_S256:
    case KDF_ALG_PBKDF2_HMAC_SHA1_C1024_S128:
        ret->a2ctx = NULL;
        break;
    default:
        ASSERT_NEVER_REACH("Invalid KDF algorithm");
    }

    return ret;
}

int kdf_derive(struct kdf *fn, byte *derived_key, size_t derived_key_len,
               const byte *password, size_t password_len, const byte *salt)
{
    size_t salt_len;

    salt_len = kdf_salt_size(fn);

    switch (fn->alg) {
    case KDF_ALG_ARGON2_ID_M6291456_P4_T1_S128:
        fn->errcode = run_argon2(derived_key, derived_key_len, password,
                                 password_len, salt, salt_len, fn->a2ctx);
        break;
    case KDF_ALG_PBKDF2_HMAC_SHA3_512_C16384_S256:
        fn->errcode =
            run_pbkdf2(derived_key, derived_key_len, password, password_len,
                       salt, salt_len, 16384, CHF_ALG_SHA3_512);
        break;
    case KDF_ALG_PBKDF2_HMAC_SHA1_C4096_S256:
        fn->errcode =
            run_pbkdf2(derived_key, derived_key_len, password, password_len,
                       salt, salt_len, 4096, CHF_ALG_SHA1);
        break;
    case KDF_ALG_PBKDF2_HMAC_SHA1_C1024_S128:
        fn->errcode =
            run_pbkdf2(derived_key, derived_key_len, password, password_len,
                       salt, salt_len, 1024, CHF_ALG_SHA1);
        break;
    default:
        ASSERT_NEVER_REACH("Invalid KDF algorithm");
    }

    scrub_memory(&password_len, sizeof(password_len));
    return fn->errcode;
}

size_t kdf_salt_size(const struct kdf *fn)
{
    return kdf_alg_salt_size(fn->alg);
}

size_t kdf_alg_salt_size(kdf_algorithm alg)
{
    switch (alg) {
    case KDF_ALG_ARGON2_ID_M6291456_P4_T1_S128:
        return 16;
    case KDF_ALG_PBKDF2_HMAC_SHA3_512_C16384_S256:
        return 32;
    case KDF_ALG_PBKDF2_HMAC_SHA1_C4096_S256:
        return 32;
    case KDF_ALG_PBKDF2_HMAC_SHA1_C1024_S128:
        return 16;
    default:
        ASSERT_NEVER_REACH("Invalid KDF algorithm");
    }
}

const char *kdf_error(const struct kdf *fn)
{
    switch (fn->errcode) {
    case 0:
        return "No error with KDF";
    case KDF_ERROR_DERIVED_KEY_TOO_LONG:
        return "KDF derived key too long";
    case KDF_ERROR_DERIVED_KEY_TOO_SHORT:
        return "KDF derived key too short";
    case KDF_ERROR_PASSWORD_TOO_LONG:
        return "KDF password too long";
    default:
        ASSERT_NEVER_REACH("Invalid KDF error code");
    }
}

void kdf_free_scrub(struct kdf *fn)
{
    if (fn == NULL) {
        return;
    }

    if (fn->a2ctx != NULL) {
        argon2_free_scrub(fn->a2ctx);
    }
    scrub_memory(fn, sizeof(struct kdf));
    free(fn);
}

static int run_argon2(byte *derived_key, size_t derived_key_len,
                      const byte *password, size_t password_len,
                      const byte *salt, size_t salt_len,
                      struct argon2_ctx *a2ctx)
{
    int a2_ret, ret;

    a2_ret = argon2_derive(a2ctx, derived_key, derived_key_len, password,
                           password_len, salt, salt_len);

    switch (a2_ret) {
    case 0:
        ret = 0;
        break;
    case ARGON2_ERROR_DERIVED_KEY_TOO_LONG:
        ret = KDF_ERROR_DERIVED_KEY_TOO_LONG;
        break;
    case ARGON2_ERROR_DERIVED_KEY_TOO_SHORT:
        ret = KDF_ERROR_DERIVED_KEY_TOO_SHORT;
        break;
    case ARGON2_ERROR_PASSWORD_TOO_LONG:
        ret = KDF_ERROR_PASSWORD_TOO_LONG;
        break;
    case ARGON2_ERROR_SALT_TOO_LONG:
        ASSERT_NEVER_REACH("Invalid salt length given to Argon2");
    default:
        ASSERT_NEVER_REACH("Unknown Argon2 error return");
    }

    scrub_memory(&password_len, sizeof(password_len));
    return ret;
}

static int run_pbkdf2(byte *derived_key, size_t derived_key_len,
                      const byte *password, size_t password_len,
                      const byte *salt, size_t salt_len,
                      unsigned int iteration_count, chf_algorithm chf_alg)
{
    int pbkdf2_ret, ret;

    pbkdf2_ret =
        pbkdf2_hmac(derived_key, derived_key_len, password, password_len, salt,
                    salt_len, iteration_count, chf_alg);

    switch (pbkdf2_ret) {
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
        ASSERT_NEVER_REACH("Invalid salt length given to PBKDF2");
    default:
        ASSERT_NEVER_REACH("Unknown PBKDF2 error return");
    }

    scrub_memory(&password_len, sizeof(password_len));
    return ret;
}
