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
    byte_t blockSizedBuffer[CHF_MAX_BLOCK_BYTES];
    byte_t digestSizedBuffer[CHF_MAX_DIGEST_BYTES];
};

struct hmac_ctx *hmac_alloc(chf_algorithm_t alg)
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
     * This check is made here as a matter of safety, in case cryptographic
     * algorithms that do not conform to this assumption (e.g., extensible hash
     * functions) are ever implemented in the underlying CHF library.
     */
    ASSERT(chf_digest_size(ret->innerCtx) <= chf_block_size(ret->innerCtx),
           "CHF not compatible with HMAC specification");

    return ret;
}

int hmac_start(struct hmac_ctx *hmac, const byte_t *key, size_t keyLen)
{
    byte_t *keyHash = hmac->digestSizedBuffer;
    byte_t *pad = hmac->blockSizedBuffer;
    size_t blockSize, i;
    int errVal = 0;

    hmac->isRunning = 1;

    /*
     * If the given key is longer than a block, replace it immediately with a
     * hash of itself. Note that hmac_alloc() guarantees that the digest size
     * of the cryptographic hash function is no larger than its block size.
     *
     * We use the innerCtx context to perform this hash for no particular
     * reason; it is just available.
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
     * Compute i_key_pad and start the inner context with it. Since we are
     * adding only one block with chf_add(), it should succeed unless there is
     * some manner of fatal flaw in the underlying CHF library.
     */
    memset(pad, 0x36, blockSize);
    for (i = 0; i < keyLen; i++) {
        pad[i] ^= key[i];
    }
    chf_start(hmac->innerCtx);
    if (chf_add(hmac->innerCtx, pad, blockSize)) {
        ASSERT_NEVER_REACH("HMAC inner context CHF initialization failed");
    }

    /*
     * Compute o_key_pad and start the outer context with it. As above, the
     * call to chf_add() should succeed.
     */
    memset(pad, 0x5C, blockSize);
    for (i = 0; i < keyLen; i++) {
        pad[i] ^= key[i];
    }
    chf_start(hmac->outerCtx);
    if (chf_add(hmac->outerCtx, pad, blockSize)) {
        ASSERT_NEVER_REACH("HMAC outer context CHF initialization failed");
    }

isErr:
    hmac->errorCode = errVal;
    return errVal;
}

int hmac_add(struct hmac_ctx *hmac, const byte_t *bytes, size_t numBytes)
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

int hmac_end(struct hmac_ctx *hmac, byte_t *digest)
{
    byte_t *innerDigest = hmac->digestSizedBuffer;
    size_t digestSize;
    int chfRes;
    int errVal = 0;

    ASSERT(hmac->isRunning, "HMAC context is not running");
    hmac->isRunning = 0;

    if (hmac->errorCode) {
        return hmac->errorCode;
    }

    /* Compute the inner digest */
    digestSize = chf_digest_size(hmac->innerCtx);
    if (chf_end(hmac->innerCtx, innerDigest)) {
        ERROR_CODE(isErr, errVal, HMAC_ERROR_MESSAGE_TOO_LONG);
    }

    /*
     * Concatenate the outer key pad (already in the outer context) and the
     * inner digest and digest that to get the HMAC.
     */
    chf_add(hmac->outerCtx, innerDigest, digestSize);
    chfRes = chf_end(hmac->outerCtx, digest);

    /*
     * The outer context computes the hash of: a single block related to the
     * key, concatenated with a single hash output. That is, there are no more
     * than two blocks of input to the outer context. If the outer-context hash
     * computation fails because the input is too long, there is some manner of
     * fatal flaw in the underlying CHF library.
     */
    ASSERT(chfRes == 0, "HMAC outer-context CHF computation failed");

isErr:
    hmac->errorCode = errVal;
    return errVal;
}

int hmac_single(struct hmac_ctx *hmac, const byte_t *key, size_t keyLen,
                const byte_t *bytes, size_t numBytes, byte_t *digest)
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
