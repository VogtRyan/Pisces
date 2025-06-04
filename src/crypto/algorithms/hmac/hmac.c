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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

struct hmac_ctx {
    struct chf_ctx *innerCtx;
    struct chf_ctx *outerCtx;
    int isRunning;
    int errorCode;

    /*
     * These two working buffers allocated inside the context are used to
     * perform computations on key material. Allocating them inside the context
     * causes hmac_free_scrub() to scrub them.
     */
    byte blockSizedBuffer[CHF_MAX_BLOCK_SIZE];
    byte digestSizedBuffer[CHF_MAX_DIGEST_SIZE];
};

struct hmac_ctx *hmac_alloc(chf_algorithm alg)
{
    struct hmac_ctx *ret =
        (struct hmac_ctx *)calloc(1, sizeof(struct hmac_ctx));
    GUARD_ALLOC(ret);

    ret->innerCtx = chf_alloc(alg);
    ret->outerCtx = chf_alloc(alg);

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
    ASSERT(chf_digest_size(ret->innerCtx) <= chf_block_size(ret->innerCtx),
           "CHF not compatible with HMAC specification");

    return ret;
}

int hmac_start(struct hmac_ctx *hmac, const byte *key, size_t keyLen)
{
    byte *keyHash = hmac->digestSizedBuffer;
    byte *pad = hmac->blockSizedBuffer;
    size_t blockSize, i;
    int chfRes;
    int errVal = 0;

    hmac->isRunning = 1;

    /*
     * If the given key is longer than a block, replace it immediately with a
     * hash of itself -- hmac_alloc() guarantees that the digest size of the
     * cryptographic hash function is no larger than its block size.
     *
     * There is no particular reason to use innerCtx for this computation; it
     * is just available.
     */
    blockSize = chf_block_size(hmac->innerCtx);
    if (keyLen > blockSize) {
        if (chf_single(hmac->innerCtx, key, keyLen, keyHash)) {
            ERROR_CODE(isErr, errVal, HMAC_ERROR_KEY_TOO_LONG);
        }
        key = keyHash;
        keyLen = chf_digest_size(hmac->innerCtx);
    }

    /*
     * Compute the inner key pad (K_0 xor ipad) and start the inner context
     * with it. Since we are adding only one block with chf_add(), the input
     * size should never be so large as to make the hash computation fail.
     */
    memset(pad, 0x36, blockSize);
    for (i = 0; i < keyLen; i++) {
        pad[i] ^= key[i];
    }
    chf_start(hmac->innerCtx);
    chfRes = chf_add(hmac->innerCtx, pad, blockSize);
    ASSERT(chfRes == 0, "HMAC inner context CHF initialization failed");

    /*
     * Compute the outer key pad (K_0 xor opad) and start the outer context
     * with it. As above, the call to chf_add() should always succeed.
     */
    memset(pad, 0x5C, blockSize);
    for (i = 0; i < keyLen; i++) {
        pad[i] ^= key[i];
    }
    chf_start(hmac->outerCtx);
    chfRes = chf_add(hmac->outerCtx, pad, blockSize);
    ASSERT(chfRes == 0, "HMAC outer context CHF initialization failed");

isErr:
    hmac->errorCode = errVal;
    return errVal;
}

int hmac_add(struct hmac_ctx *hmac, const byte *bytes, size_t numBytes)
{
    int errVal = 0;

    ASSERT(hmac->isRunning, "HMAC context is not running");
    if (hmac->errorCode) {
        return hmac->errorCode;
    }

    if (chf_add(hmac->innerCtx, bytes, numBytes)) {
        ERROR_CODE(isErr, errVal, HMAC_ERROR_MESSAGE_TOO_LONG);
    }

isErr:
    hmac->errorCode = errVal;
    return errVal;
}

int hmac_end(struct hmac_ctx *hmac, byte *digest)
{
    byte *innerDigest = hmac->digestSizedBuffer;
    size_t digestSize;
    int chfRes;
    int errVal = 0;

    ASSERT(hmac->isRunning, "HMAC context is not running");
    hmac->isRunning = 0;

    if (hmac->errorCode) {
        return hmac->errorCode;
    }

    /*
     * The outer key pad (K_0 xor opad) is already in the outer context, so we
     * only need to append the inner context's digest to it.
     */
    digestSize = chf_digest_size(hmac->innerCtx);
    if (chf_end(hmac->innerCtx, innerDigest)) {
        ERROR_CODE(isErr, errVal, HMAC_ERROR_MESSAGE_TOO_LONG);
    }
    chf_add(hmac->outerCtx, innerDigest, digestSize);
    chfRes = chf_end(hmac->outerCtx, digest);

    /*
     * The outer context computes the hash of: a single block related to the
     * key, concatenated with a single hash digest. Since the hash's digest
     * size is no greater than its block size, there are no more than two
     * blocks of input in the outer context. A two-block message should never
     * make a hash function fail from taking too large an input.
     */
    ASSERT(chfRes == 0, "HMAC outer-context CHF computation failed");

isErr:
    hmac->errorCode = errVal;
    return errVal;
}

int hmac_single(struct hmac_ctx *hmac, const byte *key, size_t keyLen,
                const byte *bytes, size_t numBytes, byte *digest)
{
    hmac_start(hmac, key, keyLen);
    hmac_add(hmac, bytes, numBytes);
    return hmac_end(hmac, digest);
}

size_t hmac_digest_size(const struct hmac_ctx *hmac)
{
    return chf_digest_size(hmac->outerCtx);
}

void hmac_copy(struct hmac_ctx *dst, const struct hmac_ctx *src)
{
    if (src == dst) {
        return;
    }

    chf_copy(dst->innerCtx, src->innerCtx);
    chf_copy(dst->outerCtx, src->outerCtx);
    dst->errorCode = src->errorCode;
    dst->isRunning = src->isRunning;
}

void hmac_free_scrub(struct hmac_ctx *hmac)
{
    if (hmac == NULL) {
        return;
    }

    if (hmac->innerCtx != NULL) {
        chf_free_scrub(hmac->innerCtx);
    }
    if (hmac->outerCtx != NULL) {
        chf_free_scrub(hmac->outerCtx);
    }

    scrub_memory(hmac, sizeof(struct hmac_ctx));
    free(hmac);
}
