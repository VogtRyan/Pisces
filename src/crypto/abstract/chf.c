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

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

struct chf_ctx {
    void *ctx;
    chf_algorithm type;
    size_t digest_size;
    size_t block_size;
    int errcode;
    bool running;
};

static inline void chf_ctx_alloc(struct chf_ctx *chf);
static inline void chf_ctx_start(struct chf_ctx *chf);
static inline int chf_ctx_add(struct chf_ctx *chf, const byte *msg,
                              size_t msg_len);
static inline int chf_ctx_end(struct chf_ctx *chf, byte *digest);
static inline void chf_ctx_copy(struct chf_ctx *dst,
                                const struct chf_ctx *src);
static inline void chf_ctx_free_scrub(struct chf_ctx *chf);

struct chf_ctx *chf_alloc(chf_algorithm alg)
{
    struct chf_ctx *ret;

    ret = (struct chf_ctx *)calloc(1, sizeof(struct chf_ctx));
    GUARD_ALLOC(ret);

    switch (alg) {
    case CHF_ALG_SHA1:
        ret->digest_size = SHA1_DIGEST_BYTES;
        ret->block_size = SHA1_BLOCK_BYTES;
        break;
    case CHF_ALG_SHA3_512:
        ret->digest_size = SHA3_512_DIGEST_BYTES;
        ret->block_size = SHA3_512_BLOCK_BYTES;
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
    chf->running = true;
    chf->errcode = 0;
    chf_ctx_start(chf);
}

int chf_add(struct chf_ctx *chf, const byte *msg, size_t msg_len)
{
    ASSERT(chf->running, "CHF context is not running");

    if (chf->errcode) {
        return chf->errcode;
    }
    if (chf_ctx_add(chf, msg, msg_len)) {
        chf->errcode = CHF_ERROR_MESSAGE_TOO_LONG;
    }

    return chf->errcode;
}

int chf_end(struct chf_ctx *chf, byte *digest)
{
    ASSERT(chf->running, "CHF context is not running");

    chf->running = false;

    if (chf->errcode) {
        return chf->errcode;
    }
    if (chf_ctx_end(chf, digest)) {
        chf->errcode = CHF_ERROR_MESSAGE_TOO_LONG;
    }

    return chf->errcode;
}

int chf_single(struct chf_ctx *chf, const byte *msg, size_t msg_len,
               byte *digest)
{
    chf_start(chf);
    chf_add(chf, msg, msg_len);
    return chf_end(chf, digest);
}

size_t chf_digest_size(const struct chf_ctx *chf)
{
    return chf->digest_size;
}

size_t chf_block_size(const struct chf_ctx *chf)
{
    return chf->block_size;
}

void chf_copy(struct chf_ctx *dst, const struct chf_ctx *src)
{
    if (src == dst) {
        return;
    }
    ASSERT(src->type == dst->type, "CHF copy with different algorithms");

    dst->errcode = src->errcode;
    dst->running = src->running;
    chf_ctx_copy(dst, src);
}

const char *chf_error(const struct chf_ctx *chf)
{
    switch (chf->errcode) {
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

static inline int chf_ctx_add(struct chf_ctx *chf, const byte *msg,
                              size_t msg_len)
{
    switch (chf->type) {
    case CHF_ALG_SHA1:
        return sha1_add((struct sha1_ctx *)chf->ctx, msg, msg_len);
    case CHF_ALG_SHA3_512:
        sha3_add((struct sha3_ctx *)chf->ctx, msg, msg_len);
        return 0;
    default:
        ASSERT_NEVER_REACH("Invalid CHF algorithm");
    }
}

static inline int chf_ctx_end(struct chf_ctx *chf, byte *digest)
{
    switch (chf->type) {
    case CHF_ALG_SHA1:
        return sha1_end((struct sha1_ctx *)chf->ctx, digest);
    case CHF_ALG_SHA3_512:
        sha3_end((struct sha3_ctx *)chf->ctx, digest);
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
