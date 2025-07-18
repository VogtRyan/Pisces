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

#include "pbkdf2.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/chf.h"
#include "crypto/algorithms/hmac/hmac.h"
#include "crypto/machine/endian.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static int alloc_hmacs(const char *password, size_t password_len,
                       const byte *salt, size_t salt_len, chf_algorithm alg,
                       struct hmac_ctx **unstarted,
                       struct hmac_ctx **pwd_preprocessed,
                       struct hmac_ctx **pwd_salt_preprocessed);
static void free_hmacs(struct hmac_ctx **hmac1, struct hmac_ctx **hmac2,
                       struct hmac_ctx **hmac3);

static bool would_overflow_counter_before_completion(size_t derived_key_len,
                                                     size_t hlen);

int pbkdf2_hmac(byte *derived_key, size_t derived_key_len,
                const char *password, size_t password_len, const byte *salt,
                size_t salt_len, unsigned int iteration_count,
                chf_algorithm alg)
{
    struct hmac_ctx *prf;
    struct hmac_ctx *pwd_preprocessed;
    struct hmac_ctx *pwd_salt_preprocessed;
    byte u[HMAC_MAX_DIGEST_SIZE];
    byte i_msof[4];
    size_t octets_from_t, on_octet, hlen;
    uint32_t i;
    unsigned int j_minus_one;
    int res;
    int errval = 0;

    ASSERT(iteration_count != 0, "PBKDF2 iteration count of zero");

    res = alloc_hmacs(password, password_len, salt, salt_len, alg, &prf,
                      &pwd_preprocessed, &pwd_salt_preprocessed);
    if (res) {
        ERROR_GOTO_SILENT_VAL(done, errval, res);
    }
    hlen = hmac_digest_size(prf);

    /*
     * Each block in the derived key is indexed by a 32-bit counter, i,
     * ranging from 1 to at most 2^32-1. No block may be indexed by i == 0.
     */
    if (would_overflow_counter_before_completion(derived_key_len, hlen)) {
        ERROR_GOTO_SILENT_VAL(done, errval, PBKDF2_ERROR_DERIVED_KEY_TOO_LONG);
    }

    /*
     * Generate a series of blocks, each hlen octets long, denoted
     * T_1, ..., T_l. Each block T_i is generated by iteration_count > 0 cycles
     * of HMAC operations, and its length is the size of the HMAC digest.
     */
    i = 1;
    while (derived_key_len > 0) {
        /*
         * T_i = U_1 xor U_2 xor ... xor U_c.
         * Compute U_1 first.
         */
        ASSERT(i != 0, "PBKDF2 loop counter overflow");
        put_big_end_32(i_msof, i);
        hmac_copy(prf, pwd_salt_preprocessed);
        hmac_add(prf, i_msof, 4);
        if (hmac_end(prf, u)) {
            /*
             * To the prf context, we added the salt then one 32-bit integer.
             * If this computation fails, it is because the salt is too long.
             */
            ERROR_GOTO_SILENT_VAL(done, errval, PBKDF2_ERROR_SALT_TOO_LONG);
        }

        /*
         * We will compute as much of T_i as we need directly in the derived
         * key buffer, so take as much of U_1 as we need.
         */
        octets_from_t = MIN(hlen, derived_key_len);
        memcpy(derived_key, u, octets_from_t);

        /*
         * Compute U_j, where 2 <= j <= c, xor'ing as much as we need of each
         * into the derived key.
         */
        for (j_minus_one = 1; j_minus_one < iteration_count; j_minus_one++) {
            hmac_copy(prf, pwd_preprocessed);
            hmac_add(prf, u, hlen);
            res = hmac_end(prf, u);

            /*
             * To the prf context this time, we added only a single HMAC
             * output, U_{j-1}. This computation should never fail on account
             * of the input being too large.
             */
            ASSERT(res == 0, "PBKDF2 U_j HMAC computation failed for j > 1");

            for (on_octet = 0; on_octet < octets_from_t; on_octet++) {
                derived_key[on_octet] ^= u[on_octet];
            }
        }

        derived_key += octets_from_t;
        derived_key_len -= octets_from_t;
        i++;
    }

done:
    free_hmacs(&prf, &pwd_preprocessed, &pwd_salt_preprocessed);
    scrub_memory(u, sizeof(u));
    return errval;
}

static int alloc_hmacs(const char *password, size_t password_len,
                       const byte *salt, size_t salt_len, chf_algorithm alg,
                       struct hmac_ctx **unstarted,
                       struct hmac_ctx **pwd_preprocessed,
                       struct hmac_ctx **pwd_salt_preprocessed)
{
    int errval = 0;

    *unstarted = hmac_alloc(alg);
    *pwd_preprocessed = hmac_alloc(alg);
    *pwd_salt_preprocessed = hmac_alloc(alg);

    if (hmac_start(*pwd_preprocessed, (const byte *)password, password_len)) {
        ERROR_GOTO_SILENT_VAL(done, errval, PBKDF2_ERROR_PASSWORD_TOO_LONG);
    }

    hmac_copy(*pwd_salt_preprocessed, *pwd_preprocessed);
    if (hmac_add(*pwd_salt_preprocessed, salt, salt_len)) {
        ERROR_GOTO_SILENT_VAL(done, errval, PBKDF2_ERROR_SALT_TOO_LONG);
    }

done:
    if (errval) {
        free_hmacs(unstarted, pwd_preprocessed, pwd_salt_preprocessed);
    }
    return errval;
}

static void free_hmacs(struct hmac_ctx **hmac1, struct hmac_ctx **hmac2,
                       struct hmac_ctx **hmac3)
{
    if (*hmac1 != NULL) {
        hmac_free_scrub(*hmac1);
        *hmac1 = NULL;
    }
    if (*hmac2 != NULL) {
        hmac_free_scrub(*hmac2);
        *hmac2 = NULL;
    }
    if (*hmac3 != NULL) {
        hmac_free_scrub(*hmac3);
        *hmac3 = NULL;
    }
}

static bool would_overflow_counter_before_completion(size_t derived_key_len,
                                                     size_t hlen)
{
    /*
     * Overflow will occur prior to deriving enough key material if:
     *   derived_key_len > (2^32-1) * hlen
     * That is true iff, with mathematical (not integer) division:
     *   derived_key_len / hlen > 2^32-1
     *
     * The inequality check is against 2^32-1 (i.e., UINT32_MAX) instead of
     * against 2^32, because the counter can take 2^32-1 possible values (it
     * can take values from 1 to 2^32-1, but never 0).
     */
#if SIZE_MAX <= UINT32_MAX
    return false;
#else
    size_t div = derived_key_len / hlen;
    if (derived_key_len % hlen == 0) {
        return div > (size_t)UINT32_MAX;
    }
    else {
        return div >= (size_t)UINT32_MAX;
    }
#endif
}
