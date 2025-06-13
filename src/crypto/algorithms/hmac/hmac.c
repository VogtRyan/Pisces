/*
 * Copyright (c) 2011-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "hmac.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/chf.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct hmac_ctx {
    struct chf_ctx *inner_ctx;
    struct chf_ctx *outer_ctx;
    bool running;
    int errcode;

    /*
     * These two working buffers allocated inside the context are used to
     * perform computations on key material. Allocating them inside the context
     * causes hmac_free_scrub() to scrub them.
     */
    byte block_sized_buffer[CHF_MAX_BLOCK_SIZE];
    byte digest_sized_buffer[CHF_MAX_DIGEST_SIZE];
};

struct hmac_ctx *hmac_alloc(chf_algorithm alg)
{
    struct hmac_ctx *ret =
        (struct hmac_ctx *)calloc(1, sizeof(struct hmac_ctx));
    GUARD_ALLOC(ret);

    ret->inner_ctx = chf_alloc(alg);
    ret->outer_ctx = chf_alloc(alg);

    /*
     * The HMAC standard assumes that the digest size of a cryptographic
     * hash function will never be larger than its block size. This
     * assumption is implicit in Step 2 of the HMAC algorithm, as detailed
     * on p.4 of FIPS 198-1, which constructs K_0 = H(K) || 00..., up to the
     * block size of of the CHF.
     *
     * Some cryptographic hash functions (e.g., extensible hash functions) do
     * not have this property.
     */
    ASSERT(chf_digest_size(ret->inner_ctx) <= chf_block_size(ret->inner_ctx),
           "CHF not compatible with HMAC specification");

    return ret;
}

int hmac_start(struct hmac_ctx *hmac, const byte *key, size_t key_len)
{
    byte *key_hash = hmac->digest_sized_buffer;
    byte *pad = hmac->block_sized_buffer;
    size_t block_size, i;
    int chfres;
    int errval = 0;

    hmac->running = true;

    /*
     * If the given key is longer than a block, replace it immediately with a
     * hash of itself -- hmac_alloc() guarantees that the digest size of the
     * cryptographic hash function is no larger than its block size.
     *
     * There is no particular reason to use inner_ctx for this computation; it
     * is just available.
     */
    block_size = chf_block_size(hmac->inner_ctx);
    if (key_len > block_size) {
        if (chf_single(hmac->inner_ctx, key, key_len, key_hash)) {
            ERROR_CODE(done, errval, HMAC_ERROR_KEY_TOO_LONG);
        }
        key = key_hash;
        key_len = chf_digest_size(hmac->inner_ctx);
    }

    /*
     * Compute the inner key pad (K_0 xor ipad) and start the inner context
     * with it. We are adding only one block of input to the hash function,
     * which should never cause it to fail from the input being too large.
     */
    memset(pad, 0x36, block_size);
    for (i = 0; i < key_len; i++) {
        pad[i] ^= key[i];
    }
    chf_start(hmac->inner_ctx);
    chfres = chf_add(hmac->inner_ctx, pad, block_size);
    ASSERT(chfres == 0, "HMAC inner context CHF initialization failed");

    /*
     * Compute the outer key pad (K_0 xor opad) and start the outer context
     * with it. As above, the call to chf_add() should always succeed.
     */
    memset(pad, 0x5C, block_size);
    for (i = 0; i < key_len; i++) {
        pad[i] ^= key[i];
    }
    chf_start(hmac->outer_ctx);
    chfres = chf_add(hmac->outer_ctx, pad, block_size);
    ASSERT(chfres == 0, "HMAC outer context CHF initialization failed");

done:
    hmac->errcode = errval;
    return errval;
}

int hmac_add(struct hmac_ctx *hmac, const byte *msg, size_t msg_len)
{
    ASSERT(hmac->running, "HMAC context is not running");

    if (hmac->errcode) {
        return hmac->errcode;
    }
    if (chf_add(hmac->inner_ctx, msg, msg_len)) {
        hmac->errcode = HMAC_ERROR_MESSAGE_TOO_LONG;
    }

    return hmac->errcode;
}

int hmac_end(struct hmac_ctx *hmac, byte *digest)
{
    byte *inner_digest = hmac->digest_sized_buffer;
    size_t digest_size;
    int chfres;
    int errval = 0;

    ASSERT(hmac->running, "HMAC context is not running");
    hmac->running = false;

    if (hmac->errcode) {
        return hmac->errcode;
    }

    /*
     * The outer key pad (K_0 xor opad) is already in the outer context, so we
     * only need to append the inner context's digest to it.
     */
    digest_size = chf_digest_size(hmac->inner_ctx);
    if (chf_end(hmac->inner_ctx, inner_digest)) {
        ERROR_CODE(done, errval, HMAC_ERROR_MESSAGE_TOO_LONG);
    }
    chf_add(hmac->outer_ctx, inner_digest, digest_size);
    chfres = chf_end(hmac->outer_ctx, digest);

    /*
     * The outer context computes the hash of: a single block related to the
     * key, concatenated with a single hash digest. Since the hash's digest
     * size is no greater than its block size, there are no more than two
     * blocks of input in the outer context. A two-block message should never
     * make a hash function fail from taking too large an input.
     */
    ASSERT(chfres == 0, "HMAC outer-context CHF computation failed");

done:
    hmac->errcode = errval;
    return errval;
}

int hmac_single(struct hmac_ctx *hmac, const byte *key, size_t key_len,
                const byte *msg, size_t msg_len, byte *digest)
{
    hmac_start(hmac, key, key_len);
    hmac_add(hmac, msg, msg_len);
    return hmac_end(hmac, digest);
}

size_t hmac_digest_size(const struct hmac_ctx *hmac)
{
    return chf_digest_size(hmac->outer_ctx);
}

void hmac_copy(struct hmac_ctx *dst, const struct hmac_ctx *src)
{
    if (src == dst) {
        return;
    }

    chf_copy(dst->inner_ctx, src->inner_ctx);
    chf_copy(dst->outer_ctx, src->outer_ctx);
    dst->errcode = src->errcode;
    dst->running = src->running;
}

void hmac_free_scrub(struct hmac_ctx *hmac)
{
    if (hmac == NULL) {
        return;
    }

    if (hmac->inner_ctx != NULL) {
        chf_free_scrub(hmac->inner_ctx);
    }
    if (hmac->outer_ctx != NULL) {
        chf_free_scrub(hmac->outer_ctx);
    }

    scrub_memory(hmac, sizeof(struct hmac_ctx));
    free(hmac);
}
