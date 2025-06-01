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

#include "chf.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/primitives/sha1/sha1.h"
#include "crypto/primitives/sha3/sha3.h"

#include <stddef.h>
#include <stdlib.h>

struct chf_ctx {
    chf_algorithm_t type;
    void *ctx;
    int isRunning;
    int errorCode;
    size_t digestBytes;
    size_t blockBytes;
};

/*
 * Calls the given operations on the underlying hash context. The chf->type
 * value must be set.
 */
static inline void chf_ctx_alloc(struct chf_ctx *chf);
static inline void chf_ctx_start(struct chf_ctx *chf);
static inline int chf_ctx_add(struct chf_ctx *chf, const byte_t *input,
                              size_t inputLen);
static inline int chf_ctx_end(struct chf_ctx *chf, byte_t *output);
static inline void chf_ctx_copy(struct chf_ctx *dst,
                                const struct chf_ctx *src);
static inline void chf_ctx_free_scrub(struct chf_ctx *chf);

struct chf_ctx *chf_alloc(chf_algorithm_t alg)
{
    struct chf_ctx *ret = (struct chf_ctx *)calloc(1, sizeof(struct chf_ctx));
    GUARD_ALLOC(ret);

    switch (alg) {
    case CHF_ALG_SHA1:
        ret->digestBytes = SHA1_DIGEST_BYTES;
        ret->blockBytes = SHA1_BLOCK_BYTES;
        break;
    case CHF_ALG_SHA3_512:
        ret->digestBytes = SHA3_512_DIGEST_BYTES;
        ret->blockBytes = SHA3_512_BLOCK_BYTES;
        break;
    default:
        ASSERT_NEVER_REACH("Invalid CHF algorithm");
    }

    ret->type = alg;
    chf_ctx_alloc(ret);
    return ret;
}

void chf_start(struct chf_ctx *chf)
{
    chf->isRunning = 1;
    chf->errorCode = 0;
    chf_ctx_start(chf);
}

int chf_add(struct chf_ctx *chf, const byte_t *input, size_t inputLen)
{
    ASSERT(chf->isRunning, "CHF context is not running");

    if (chf->errorCode) {
        return chf->errorCode;
    }
    if (chf_ctx_add(chf, input, inputLen)) {
        ERROR_SET(chf->errorCode, CHF_ERROR_MESSAGE_TOO_LONG);
    }

    return chf->errorCode;
}

int chf_end(struct chf_ctx *chf, byte_t *output)
{
    ASSERT(chf->isRunning, "CHF context is not running");

    chf->isRunning = 0;

    if (chf->errorCode) {
        return chf->errorCode;
    }
    if (chf_ctx_end(chf, output)) {
        ERROR_SET(chf->errorCode, CHF_ERROR_MESSAGE_TOO_LONG);
    }

    return chf->errorCode;
}

int chf_single(struct chf_ctx *chf, const byte_t *input, size_t inputLen,
               byte_t *output)
{
    chf_start(chf);
    chf_add(chf, input, inputLen);
    return chf_end(chf, output);
}

size_t chf_digest_size(const struct chf_ctx *chf)
{
    return chf->digestBytes;
}

size_t chf_block_size(const struct chf_ctx *chf)
{
    return chf->blockBytes;
}

void chf_copy(struct chf_ctx *dst, const struct chf_ctx *src)
{
    if (src == dst) {
        return;
    }
    ASSERT(src->type == dst->type, "CHF copy with different algorithms");

    dst->errorCode = src->errorCode;
    dst->isRunning = src->isRunning;
    chf_ctx_copy(dst, src);
}

const char *chf_error(const struct chf_ctx *chf)
{
    switch (chf->errorCode) {
    case 0:
        return "No error in CHF context";
    case CHF_ERROR_MESSAGE_TOO_LONG:
        return "Message length exceeded CHF maximum";
    default:
        ASSERT_NEVER_REACH("Invalid CHF error code");
    }
}

void chf_free_scrub(struct chf_ctx *chf)
{
    if (chf != NULL) {
        chf_ctx_free_scrub(chf);
        scrub_memory(chf, sizeof(struct chf_ctx));
        free(chf);
    }
}

static inline void chf_ctx_alloc(struct chf_ctx *chf)
{
    switch (chf->type) {
    case CHF_ALG_SHA1:
        chf->ctx = sha1_alloc();
        break;
    case CHF_ALG_SHA3_512:
        chf->ctx = sha3_alloc();
        break;
    default:
        ASSERT_NEVER_REACH("Invalid CHF algorithm");
    }
}

static inline void chf_ctx_start(struct chf_ctx *chf)
{
    switch (chf->type) {
    case CHF_ALG_SHA1:
        sha1_start((struct sha1_ctx *)chf->ctx);
        break;
    case CHF_ALG_SHA3_512:
        sha3_512_start((struct sha3_ctx *)chf->ctx);
        break;
    default:
        ASSERT_NEVER_REACH("Invalid CHF algorithm");
    }
}

static inline int chf_ctx_add(struct chf_ctx *chf, const byte_t *input,
                              size_t inputLen)
{
    switch (chf->type) {
    case CHF_ALG_SHA1:
        return sha1_add((struct sha1_ctx *)chf->ctx, input, inputLen);
    case CHF_ALG_SHA3_512:
        sha3_add((struct sha3_ctx *)chf->ctx, input, inputLen);
        return 0;
    default:
        ASSERT_NEVER_REACH("Invalid CHF algorithm");
    }
}

static inline int chf_ctx_end(struct chf_ctx *chf, byte_t *output)
{
    switch (chf->type) {
    case CHF_ALG_SHA1:
        return sha1_end((struct sha1_ctx *)chf->ctx, output);
    case CHF_ALG_SHA3_512:
        sha3_end((struct sha3_ctx *)chf->ctx, output);
        return 0;
    default:
        ASSERT_NEVER_REACH("Invalid CHF algorithm");
    }
}

static inline void chf_ctx_copy(struct chf_ctx *dst, const struct chf_ctx *src)
{
    /* Assumes src != dst, which must be guaranteed by calling function */
    switch (src->type) {
    case CHF_ALG_SHA1:
        sha1_copy((struct sha1_ctx *)dst->ctx,
                  (const struct sha1_ctx *)src->ctx);
        break;
    case CHF_ALG_SHA3_512:
        sha3_copy((struct sha3_ctx *)dst->ctx,
                  (const struct sha3_ctx *)src->ctx);
        break;
    default:
        ASSERT_NEVER_REACH("Invalid CHF algorithm");
    }
}

static inline void chf_ctx_free_scrub(struct chf_ctx *chf)
{
    if (chf->ctx == NULL) {
        return;
    }

    switch (chf->type) {
    case CHF_ALG_SHA1:
        sha1_free_scrub((struct sha1_ctx *)chf->ctx);
        break;
    case CHF_ALG_SHA3_512:
        sha3_free_scrub((struct sha3_ctx *)chf->ctx);
        break;
    default:
        ASSERT_NEVER_REACH("Invalid CHF algorithm");
    }
    chf->ctx = NULL;
}
