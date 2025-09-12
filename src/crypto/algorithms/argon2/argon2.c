/*
 * Copyright (c) 2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "crypto/algorithms/argon2/argon2.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/algorithms/argon2/message_barrier.h"
#include "crypto/machine/endian.h"
#include "crypto/primitives/blake2b/blake2b.h"

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BLOCK_BYTES (1024U)
#define NUM_SLICES  (4U)

#define COMMAND_RUN_COMPUTATION  (1)
#define COMMAND_TERMINATE_THREAD (2)

#define Y_ARGON2D  (0)
#define Y_ARGON2I  (1)
#define Y_ARGON2ID (2)

#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#define UNUSED(varname) (void)(varname)

#if UINT32_MAX > SIZE_MAX
#error "Argon2 implementation assumes size_t can hold any uint32_t"
#endif

#if SIZE_MAX > UINT32_MAX
#define SIZET_TO_UINT32T_SAFE(val) ((val) <= (size_t)UINT32_MAX)
#else
#define SIZET_TO_UINT32T_SAFE(val) (true)
#endif

#if ULONG_MAX > UINT32_MAX
#define ULONG_TO_UINT32T_SAFE(val) ((val) <= (unsigned long)UINT32_MAX)
#else
#define ULONG_TO_UINT32T_SAFE(val) (true)
#endif

struct argon2_input_data {
    const byte *k_secret;
    const byte *password;
    const byte *salt;
    const byte *x_associated;
    uint32_t k_secret_len;
    uint32_t password_len;
    uint32_t salt_len;
    uint32_t x_associated_len;
};

struct argon2_ctx {
    byte *working_mem;               /* Flattened RFC 9106 B[][] array */
    struct blake2b_ctx **b2bctxs;    /* Indices [0, num_threads) */
    struct message_barrier *barrier; /* NULL iff single-threaded */
    pthread_t *worker_threads;       /* Indices [0, num_threads-1), or NULL */
    byte h0[64];                     /* Pre-hashing digest */
    uint32_t m;                      /* Requested memory size (kb) */
    uint32_t m_prime;                /* Actual working memory size (kb) */
    uint32_t num_threads;            /* Number of threads (>= 1) */
    uint32_t p;                      /* Number of lanes */
    uint32_t q;                      /* Num. columns of 1024-byte blocks */
    uint32_t t;                      /* Passes */
    byte y;                          /* Argon2 variant (0, 1, or 2) */
};

struct thread_ctx {
    struct argon2_ctx *a2ctx;
    uint32_t thread_index; /* Main thread index: num_threads-1 */
};

struct segment_ref {
    uint32_t pass;
    uint32_t slice;
    uint32_t lane;
};

struct block_ref {
    uint32_t pass;
    uint32_t slice;
    uint32_t lane;
    uint32_t index_in_lane;
};

struct variant_i_jvals {
    byte buf[BLOCK_BYTES];
    uint64_t prefix;
    int vals_remaining;
};

static void validated_derive(struct argon2_ctx *a2ctx, byte *derived_key,
                             uint32_t derived_key_len,
                             const struct argon2_input_data *in);
static void *worker_main(void *worker_thread_ctx);

static void compute_h0(struct thread_ctx *tctx, uint32_t derived_key_len,
                       const struct argon2_input_data *in);
static void compute_segments(struct thread_ctx *tctx, uint32_t pass,
                             uint32_t slice);
static void compute_segment(struct thread_ctx *tctx,
                            struct segment_ref segment);
static void compute_opening_blocks(struct thread_ctx *tctx,
                                   struct segment_ref segment);
static void finalize_key_derivation(struct thread_ctx *tctx, byte *derived_key,
                                    uint32_t derived_key_len);

static void compute_j1_j2_d(const struct argon2_ctx *a2ctx, uint32_t *j1,
                            uint32_t *j2, struct block_ref block);
static void compute_j1_j2_i(struct argon2_ctx *a2ctx, uint32_t *j1,
                            uint32_t *j2, struct segment_ref segment,
                            struct variant_i_jvals *jvals);
static void map_to_l_z(struct argon2_ctx *a2ctx, uint32_t *l, uint32_t *z,
                       uint32_t j1, uint32_t j2, struct block_ref block);
static inline byte *get_block(const struct argon2_ctx *a2ctx, uint32_t lane,
                              uint32_t block_in_lane);

static void hash_prime(struct blake2b_ctx *b2bctx, byte *digest,
                       uint32_t digest_len, const byte *msg, uint32_t msg_len);

static void compression_fn_g(byte *output_block, const byte *block_x,
                             const byte *block_y, bool xor_output);

struct argon2_ctx *argon2_alloc(argon2_variant y_variant,
                                unsigned long m_memsize_kb,
                                unsigned long p_parallelism,
                                unsigned long t_passes,
                                unsigned long max_threads)
{
    struct argon2_ctx *ret;
    struct thread_ctx *tctx;
    uint32_t i;

    ASSERT(p_parallelism >= 1 && p_parallelism < (1UL << 24),
           "Invalid p value (%lu)", p_parallelism);

    ASSERT(m_memsize_kb >= 8 * p_parallelism,
           "m (%lu) not at least 8p (p=%lu, 8p=%lu)", m_memsize_kb,
           p_parallelism, 8 * p_parallelism);
    ASSERT(ULONG_TO_UINT32T_SAFE(m_memsize_kb), "m too large (%lu)",
           m_memsize_kb);

    ASSERT(t_passes > 0, "t must be positive");
    ASSERT(ULONG_TO_UINT32T_SAFE(t_passes), "t too large (%lu)", t_passes);

    ret = (struct argon2_ctx *)calloc(1, sizeof(struct argon2_ctx));
    GUARD_ALLOC(ret);

    ret->m = (uint32_t)m_memsize_kb;
    ret->p = (uint32_t)p_parallelism;
    ret->t = (uint32_t)t_passes;

    switch (y_variant) {
    case ARGON2_VARIANT_D:
        ret->y = Y_ARGON2D;
        break;
    case ARGON2_VARIANT_I:
        ret->y = Y_ARGON2I;
        break;
    case ARGON2_VARIANT_ID:
        ret->y = Y_ARGON2ID;
        break;
    default:
        ASSERT_NEVER_REACH("Invalid Argon2 variant");
    }

    /* q <= m' = p * q <= m */
    ret->m_prime = (NUM_SLICES * ret->p) * (ret->m / (NUM_SLICES * ret->p));
    ret->q = ret->m_prime / ret->p;

    /*
     * Guard against overflow by guaranteeing (m' * 1024) = (p * q * 1024)
     * fits in a size_t. Casting uint32_t to size_t is safe on any platform
     * supported by this implementation.
     */
    ASSERT((size_t)ret->m_prime <= SIZE_MAX / BLOCK_BYTES,
           "Overflow of memory size computation (m'=%lu, m=%lu, p=%lu)",
           (unsigned long)ret->m_prime, m_memsize_kb, p_parallelism);
    ret->working_mem = (byte *)malloc((size_t)ret->m_prime * BLOCK_BYTES);
    GUARD_ALLOC(ret->working_mem);

    if (max_threads > p_parallelism ||
        max_threads == ARGON2_MAX_THREADS_AUTO) {
        ret->num_threads = ret->p;
    }
    else {
        ret->num_threads = (uint32_t)max_threads;
    }

    ret->b2bctxs = (struct blake2b_ctx **)calloc(ret->num_threads,
                                                 sizeof(struct blake2b_ctx *));
    GUARD_ALLOC(ret->b2bctxs);
    for (i = 0; i < ret->num_threads; i++) {
        ret->b2bctxs[i] = blake2b_alloc();
    }

    if (ret->num_threads == 1) {
        ret->barrier = NULL;
        ret->worker_threads = NULL;
        return ret;
    }

    ret->barrier = message_barrier_alloc(ret->num_threads);

    ret->worker_threads =
        (pthread_t *)calloc(ret->num_threads - 1, sizeof(pthread_t));
    GUARD_ALLOC(ret->worker_threads);

    for (i = 0; i < ret->num_threads - 1; i++) {
        /* worker_main() is responsible for freeing the thread context */
        tctx = (struct thread_ctx *)calloc(1, sizeof(struct thread_ctx));
        GUARD_ALLOC(tctx);
        tctx->a2ctx = ret;
        tctx->thread_index = i;

        if (pthread_create(ret->worker_threads + i, NULL, worker_main, tctx)) {
            FATAL_ERROR("Could not create worker thread");
        }
    }

    return ret;
}

int argon2_derive(struct argon2_ctx *ctx, byte *derived_key,
                  size_t derived_key_len, const char *password,
                  size_t password_len, const byte *salt, size_t salt_len)
{
    int ret;

    ret = argon2_derive_opt(ctx, derived_key, derived_key_len, password,
                            password_len, salt, salt_len, NULL, 0, NULL, 0);

    scrub_memory(&password_len, sizeof(password_len));
    return ret;
}

int argon2_derive_opt(struct argon2_ctx *ctx, byte *derived_key,
                      size_t derived_key_len, const char *password,
                      size_t password_len, const byte *salt, size_t salt_len,
                      const byte *k_secret, size_t k_secret_len,
                      const byte *x_associated, size_t x_associated_len)
{
    struct argon2_input_data in;
    int errval = 0;

    if (SIZET_TO_UINT32T_SAFE(password_len) == false) {
        ERROR_GOTO_SILENT_VAL(done, errval, ARGON2_ERROR_PASSWORD_TOO_LONG);
    }
    if (SIZET_TO_UINT32T_SAFE(salt_len) == false) {
        ERROR_GOTO_SILENT_VAL(done, errval, ARGON2_ERROR_SALT_TOO_LONG);
    }
    if (SIZET_TO_UINT32T_SAFE(derived_key_len) == false) {
        ERROR_GOTO_SILENT_VAL(done, errval, ARGON2_ERROR_DERIVED_KEY_TOO_LONG);
    }
    if (derived_key_len < 4) {
        ERROR_GOTO_SILENT_VAL(done, errval,
                              ARGON2_ERROR_DERIVED_KEY_TOO_SHORT);
    }
    if (SIZET_TO_UINT32T_SAFE(k_secret_len) == false) {
        ERROR_GOTO_SILENT_VAL(done, errval, ARGON2_ERROR_SECRET_DATA_TOO_LONG);
    }
    if (SIZET_TO_UINT32T_SAFE(x_associated_len) == false) {
        ERROR_GOTO_SILENT_VAL(done, errval,
                              ARGON2_ERROR_ASSOCIATED_DATA_TOO_LONG);
    }

    in.k_secret = k_secret;
    in.password = (const byte *)password;
    in.salt = salt;
    in.x_associated = x_associated;

    in.k_secret_len = (uint32_t)k_secret_len;
    in.password_len = (uint32_t)password_len;
    in.salt_len = (uint32_t)salt_len;
    in.x_associated_len = (uint32_t)x_associated_len;

    validated_derive(ctx, derived_key, (uint32_t)derived_key_len, &in);

done:
    scrub_memory(&in, sizeof(in));
    scrub_memory(&password_len, sizeof(password_len));
    scrub_memory(&k_secret_len, sizeof(k_secret_len));
    return errval;
}

void argon2_free_scrub(struct argon2_ctx *ctx)
{
    uint32_t i;

    if (ctx == NULL) {
        return;
    }

    if (ctx->num_threads > 1) {
        message_barrier_write(ctx->barrier, COMMAND_TERMINATE_THREAD);
        for (i = 0; i < ctx->num_threads - 1; i++) {
            pthread_join(ctx->worker_threads[i], NULL);
        }
        free(ctx->worker_threads);
        message_barrier_free(ctx->barrier);
    }

    for (i = 0; i < ctx->num_threads; i++) {
        blake2b_free_scrub(ctx->b2bctxs[i]);
    }
    free(ctx->b2bctxs);

    /* Multiplication was checked for safety during argon2_alloc() */
    scrub_memory(ctx->working_mem, (size_t)ctx->m_prime * BLOCK_BYTES);
    free(ctx->working_mem);

    scrub_memory(ctx, sizeof(struct argon2_ctx));
    free(ctx);
}

static void validated_derive(struct argon2_ctx *a2ctx, byte *derived_key,
                             uint32_t derived_key_len,
                             const struct argon2_input_data *in)
{
    struct thread_ctx main_thread_ctx;
    uint32_t on_pass, on_slice;

    main_thread_ctx.a2ctx = a2ctx;
    main_thread_ctx.thread_index = a2ctx->num_threads - 1;

    compute_h0(&main_thread_ctx, derived_key_len, in);

    if (a2ctx->num_threads > 1) {
        message_barrier_write(a2ctx->barrier, COMMAND_RUN_COMPUTATION);
    }

    for (on_pass = 0; on_pass < a2ctx->t; on_pass++) {
        for (on_slice = 0; on_slice < NUM_SLICES; on_slice++) {
            compute_segments(&main_thread_ctx, on_pass, on_slice);
            if (a2ctx->num_threads > 1) {
                message_barrier_wait(a2ctx->barrier);
            }
        }
    }

    finalize_key_derivation(&main_thread_ctx, derived_key, derived_key_len);
}

static void *worker_main(void *worker_thread_ctx)
{
    struct argon2_ctx *a2ctx;
    struct thread_ctx *tctx;
    uint32_t on_pass, on_slice;
    int command;

    tctx = (struct thread_ctx *)worker_thread_ctx;
    a2ctx = tctx->a2ctx;

    while (1) {
        command = message_barrier_read(a2ctx->barrier);

        switch (command) {
        case COMMAND_RUN_COMPUTATION:
            for (on_pass = 0; on_pass < a2ctx->t; on_pass++) {
                for (on_slice = 0; on_slice < NUM_SLICES; on_slice++) {
                    compute_segments(tctx, on_pass, on_slice);
                    message_barrier_wait(a2ctx->barrier);
                }
            }
            break;
        case COMMAND_TERMINATE_THREAD:
            free(worker_thread_ctx);
            return NULL;
        default:
            ASSERT_NEVER_REACH("Unknown command given to Argon2 worker");
        }
    }
}

static void compute_h0(struct thread_ctx *tctx, uint32_t derived_key_len,
                       const struct argon2_input_data *in)
{
    struct argon2_ctx *a2ctx;
    struct blake2b_ctx *b2bctx;
    byte opening[28];
    byte len_input[4];
    int b2bret;

    a2ctx = tctx->a2ctx;
    b2bctx = a2ctx->b2bctxs[tctx->thread_index];

    put_little_end_32(opening, a2ctx->p);
    put_little_end_32(opening + 4, derived_key_len);
    put_little_end_32(opening + 8, a2ctx->m_prime);
    put_little_end_32(opening + 12, a2ctx->t);
    opening[16] = (byte)0x13;
    opening[17] = opening[18] = opening[19] = 0;
    opening[20] = a2ctx->y;
    opening[21] = opening[22] = opening[23] = 0;
    put_little_end_32(opening + 24, in->password_len);

    blake2b_start(b2bctx, 64, NULL, 0);
    blake2b_add(b2bctx, opening, sizeof(opening));
    blake2b_add(b2bctx, (const byte *)in->password, (size_t)in->password_len);

    put_little_end_32(len_input, in->salt_len);
    blake2b_add(b2bctx, len_input, sizeof(len_input));
    blake2b_add(b2bctx, in->salt, (size_t)in->salt_len);

    put_little_end_32(len_input, in->k_secret_len);
    blake2b_add(b2bctx, len_input, sizeof(len_input));
    blake2b_add(b2bctx, in->k_secret, (size_t)in->k_secret_len);

    put_little_end_32(len_input, in->x_associated_len);
    blake2b_add(b2bctx, len_input, sizeof(len_input));
    blake2b_add(b2bctx, in->x_associated, (size_t)in->x_associated_len);

    /* Should never fail, per the limits set by RFC 9106 */
    b2bret = blake2b_end(b2bctx, a2ctx->h0);
    ASSERT(b2bret == 0, "BLAKE2b computation of H_0 failed");

    scrub_memory(opening, sizeof(opening));
    scrub_memory(len_input, sizeof(len_input));
}

static void compute_segments(struct thread_ctx *tctx, uint32_t pass,
                             uint32_t slice)
{
    struct argon2_ctx *a2ctx;
    struct segment_ref segment;
    uint32_t lane_lb, lane_ub;
    uint32_t min_lanes, threads_with_extra_lane;

    a2ctx = tctx->a2ctx;

    min_lanes = a2ctx->p / a2ctx->num_threads;
    threads_with_extra_lane = a2ctx->p % a2ctx->num_threads;
    if (tctx->thread_index < threads_with_extra_lane) {
        lane_lb = tctx->thread_index * (min_lanes + 1);
        lane_ub = lane_lb + min_lanes + 1;
    }
    else {
        lane_lb = threads_with_extra_lane * (min_lanes + 1) +
                  (tctx->thread_index - threads_with_extra_lane) * min_lanes;
        lane_ub = lane_lb + min_lanes;
    }

    segment.pass = pass;
    segment.slice = slice;
    for (segment.lane = lane_lb; segment.lane < lane_ub; segment.lane++) {
        compute_segment(tctx, segment);
    }
}

static void compute_segment(struct thread_ctx *tctx,
                            struct segment_ref segment)
{
    struct argon2_ctx *a2ctx;
    struct block_ref block;
    struct variant_i_jvals jvals_i;
    byte *input_x, *input_y, *output;
    uint32_t slice_start_index, slice_end_index;
    uint32_t j1, j2, l, z;
    bool use_variant_i;

    a2ctx = tctx->a2ctx;

    use_variant_i =
        (a2ctx->y == Y_ARGON2I ||
         (a2ctx->y == Y_ARGON2ID && segment.pass == 0 && segment.slice <= 1));
    if (use_variant_i) {
        /*
         * The initial state of jvals_i represents "no values remaining using
         * a prefix of 0". The next call to compute_j1_j2_i() will produce the
         * first value that uses a prefix of 1.
         */
        memset(&jvals_i, 0, sizeof(jvals_i));
    }

    slice_start_index = segment.slice * (a2ctx->q / NUM_SLICES);
    slice_end_index = slice_start_index + (a2ctx->q / NUM_SLICES);

    /*
     * Build a reference to the first block that will be computed using the
     * <J_1, J_2> -> <l, z> method from RFC 9106, section 3.2, steps 5-6.
     */
    if (segment.slice == 0 && segment.pass == 0) {
        compute_opening_blocks(tctx, segment);
        block.index_in_lane = 2;
    }
    else {
        block.index_in_lane = slice_start_index;
    }
    block.lane = segment.lane;
    block.pass = segment.pass;
    block.slice = segment.slice;

    while (block.index_in_lane < slice_end_index) {
        if (use_variant_i) {
            compute_j1_j2_i(a2ctx, &j1, &j2, segment, &jvals_i);
        }
        else {
            compute_j1_j2_d(a2ctx, &j1, &j2, block);
        }
        map_to_l_z(a2ctx, &l, &z, j1, j2, block);

        output = get_block(a2ctx, block.lane, block.index_in_lane);
        if (block.index_in_lane == 0) {
            input_x = get_block(a2ctx, block.lane, a2ctx->q - 1);
        }
        else {
            input_x = get_block(a2ctx, block.lane, block.index_in_lane - 1);
        }
        input_y = get_block(a2ctx, l, z);
        compression_fn_g(output, input_x, input_y, (block.pass != 0));

        block.index_in_lane++;
    }
}

static void compute_opening_blocks(struct thread_ctx *tctx,
                                   struct segment_ref segment)
{
    struct argon2_ctx *a2ctx;
    struct blake2b_ctx *b2bctx;
    byte hash_input[72];
    byte *output_block;

    a2ctx = tctx->a2ctx;
    b2bctx = a2ctx->b2bctxs[tctx->thread_index];

    memcpy(hash_input, a2ctx->h0, 64);
    memset(hash_input + 64, 0, 4);

    put_little_end_32(hash_input + 68, segment.lane);

    hash_input[64] = 0;
    output_block = get_block(a2ctx, segment.lane, 0);
    hash_prime(b2bctx, output_block, BLOCK_BYTES, hash_input, 72);

    hash_input[64] = 1;
    output_block = get_block(a2ctx, segment.lane, 1);
    hash_prime(b2bctx, output_block, BLOCK_BYTES, hash_input, 72);

    scrub_memory(hash_input, sizeof(hash_input));
}

static void finalize_key_derivation(struct thread_ctx *tctx, byte *derived_key,
                                    uint32_t derived_key_len)
{
    struct argon2_ctx *a2ctx;
    struct blake2b_ctx *b2bctx;
    byte c[BLOCK_BYTES];
    uint32_t on_lane, on_byte;
    byte *last_seg_in_lane;

    a2ctx = tctx->a2ctx;
    b2bctx = a2ctx->b2bctxs[tctx->thread_index];

    memcpy(c, get_block(a2ctx, 0, a2ctx->q - 1), BLOCK_BYTES);
    for (on_lane = 1; on_lane < a2ctx->p; on_lane++) {
        last_seg_in_lane = get_block(a2ctx, on_lane, a2ctx->q - 1);
        for (on_byte = 0; on_byte < BLOCK_BYTES; on_byte++) {
            c[on_byte] ^= last_seg_in_lane[on_byte];
        }
    }

    hash_prime(b2bctx, derived_key, derived_key_len, c, BLOCK_BYTES);

    scrub_memory(c, sizeof(c));
}

static void compute_j1_j2_d(const struct argon2_ctx *a2ctx, uint32_t *j1,
                            uint32_t *j2, struct block_ref block)
{
    byte *extraction_blk;

    /*
     * RFC 9106 section 3.4.1.1 is unclear on how to derive J_1 and J_2 when
     * index_in_lane (called "j" in the RFC) is 0. However, the context
     * provided by section 3.2 step 6 indicates that the computation of
     * index_in_lane-1 ("j-1" in the RFC) should wrap to q-1.
     */
    if (block.index_in_lane == 0) {
        extraction_blk = get_block(a2ctx, block.lane, a2ctx->q - 1);
    }
    else {
        extraction_blk = get_block(a2ctx, block.lane, block.index_in_lane - 1);
    }
    *j1 = get_little_end_32(extraction_blk);
    *j2 = get_little_end_32(extraction_blk + 4);
}

static void compute_j1_j2_i(struct argon2_ctx *a2ctx, uint32_t *j1,
                            uint32_t *j2, struct segment_ref segment,
                            struct variant_i_jvals *jvals)
{
    byte zeros[BLOCK_BYTES];
    byte rhs[BLOCK_BYTES];
    const byte *jval_loc;

    if (jvals->vals_remaining > 0) {
        jval_loc = jvals->buf + BLOCK_BYTES - jvals->vals_remaining * 8;
        jvals->vals_remaining--;
    }
    else {
        /*
         * In RFC 9106 section 3.4.1.2, we compute Z || LE64(i) for values
         * i >= 1. Call that value i the "prefix" for the associated set of 128
         * <J_1, J_2> value pairs.
         */
        jvals->prefix++;

        put_little_end_64(rhs, (uint64_t)segment.pass);
        put_little_end_64(rhs + 8, (uint64_t)segment.lane);
        put_little_end_64(rhs + 16, (uint64_t)segment.slice);
        put_little_end_64(rhs + 24, (uint64_t)(a2ctx->m_prime));
        put_little_end_64(rhs + 32, (uint64_t)(a2ctx->t));
        put_little_end_64(rhs + 40, (uint64_t)(a2ctx->y));
        put_little_end_64(rhs + 48, (uint64_t)(jvals->prefix));
        memset(rhs + 56, 0, BLOCK_BYTES - 56);

        memset(zeros, 0, BLOCK_BYTES);

        compression_fn_g(rhs, zeros, rhs, false);
        compression_fn_g(jvals->buf, zeros, rhs, false);

        jval_loc = jvals->buf;
        jvals->vals_remaining = BLOCK_BYTES / 8 - 1;
    }

    *j1 = get_little_end_32(jval_loc);
    *j2 = get_little_end_32(jval_loc + 4);
}

static void map_to_l_z(struct argon2_ctx *a2ctx, uint32_t *l, uint32_t *z,
                       uint32_t j1, uint32_t j2, struct block_ref block)
{
    uint32_t index_in_slice, slice_size;
    uint32_t offset;
    uint32_t w_size, w_start;
    uint32_t x, y, zz;

    /* Determine the target lane l */
    if (block.pass == 0 && block.slice == 0) {
        *l = block.lane;
    }
    else {
        *l = j2 % a2ctx->p;
    }

    slice_size = a2ctx->q / NUM_SLICES;
    index_in_slice = block.index_in_lane - block.slice * slice_size;

    /* Compute |W| and find the first index of W */
    if (*l == block.lane) {
        if (block.pass == 0 || block.slice == NUM_SLICES - 1) {
            /*
             * index_in_lane > 1, because on pass 0, working_mem[lane][0] and
             * working_mem[lane][1] are already computed. So, w_size > 0.
             */
            w_size = block.index_in_lane - 1;
            w_start = 0;
        }
        else {
            w_size = 3 * slice_size + index_in_slice - 1;
            /*
             * The first index of the most recently completed 3 segments is
             * the start of the "next" (speaking circularly) slice.
             */
            w_start = ((block.slice + 1) % NUM_SLICES) * slice_size;
        }
    }
    else {
        offset = (index_in_slice == 0 ? 1 : 0);
        if (block.pass == 0 || block.slice == NUM_SLICES - 1) {
            /*
             * Here, slice != 0, because on pass 0 slice 0, *l == lane. So,
             * w_size > 0.
             */
            w_size = block.slice * slice_size - offset;
            w_start = 0;
        }
        else {
            w_size = 3 * slice_size - offset;
            w_start = ((block.slice + 1) % NUM_SLICES) * slice_size;
        }
    }

    /*
     * Compute the offset into W, zz, where z will be located. Since
     * w_size > 0, it is guaranteed that 0 <= y < w_size.
     */
    x = (uint32_t)(((uint64_t)j1 * j1) >> 32);
    y = (uint32_t)(((uint64_t)w_size * x) >> 32);
    zz = w_size - 1 - y;

    /* Translate the zz offset into a z column index */
    *z = (uint32_t)(((uint64_t)w_start + zz) % a2ctx->q);
}

static inline byte *get_block(const struct argon2_ctx *a2ctx, uint32_t lane,
                              uint32_t block_in_lane)
{
    /*
     * The overflow check in argon2_alloc() guarantees the math is safe,
     * provided 0 <= lane < ctx->p and 0 <= block_in_lane < ctx->q.
     */
    return a2ctx->working_mem + ((size_t)lane * a2ctx->q * BLOCK_BYTES) +
           ((size_t)block_in_lane * BLOCK_BYTES);
}

static void hash_prime(struct blake2b_ctx *b2bctx, byte *digest,
                       uint32_t digest_len, const byte *msg, uint32_t msg_len)
{
    byte working_hash[64];
    byte digest_len_le[4];
    uint32_t i, r;
    int b2bret;

    put_little_end_32(digest_len_le, digest_len);

    if (digest_len <= 64) {
        blake2b_start(b2bctx, (size_t)digest_len, NULL, 0);
        blake2b_add(b2bctx, digest_len_le, sizeof(digest_len_le));
        blake2b_add(b2bctx, msg, (size_t)msg_len);
        b2bret = blake2b_end(b2bctx, digest);
        ASSERT(b2bret == 0, "H' short-tag computation failed");
        return;
    }

    /* r >= 1 */
    r = digest_len / 32 - 2;
    if (digest_len % 32 != 0) {
        r++;
    }

    blake2b_start(b2bctx, sizeof(working_hash), NULL, 0);
    blake2b_add(b2bctx, digest_len_le, sizeof(digest_len_le));
    blake2b_add(b2bctx, msg, (size_t)msg_len);
    b2bret = blake2b_end(b2bctx, working_hash);
    ASSERT(b2bret == 0, "H' first computation failed");
    memcpy(digest, working_hash, 32);
    digest += 32;

    for (i = 1; i < r; i++) {
        b2bret = blake2b_single(b2bctx, working_hash, sizeof(working_hash),
                                NULL, 0, working_hash, sizeof(working_hash));
        ASSERT(b2bret == 0, "H' inner computation failed");
        memcpy(digest, working_hash, 32);
        digest += 32;
    }

    b2bret = blake2b_single(b2bctx, working_hash, sizeof(working_hash), NULL,
                            0, digest, (size_t)(digest_len - 32 * r));
    ASSERT(b2bret == 0, "H' final computation failed");

    scrub_memory(working_hash, sizeof(working_hash));
}

/*
 * This implementation of G() is algorithmically generated (see
 * generate_argon2.c). It uses a flat array, f[128], to store all 64 registers,
 * instead of building an array v[16] of eight registers as input for each call
 * to permutation function P().
 */
static void compression_fn_g(byte *output_block, const byte *block_x,
                             const byte *block_y, bool xor_output)
{
    uint64_t f[BLOCK_BYTES / 8];
    byte r[BLOCK_BYTES];
    byte z[BLOCK_BYTES];
    size_t i;

    for (i = 0; i < BLOCK_BYTES; i++) {
        r[i] = block_x[i] ^ block_y[i];
    }

    for (i = 0; i < BLOCK_BYTES / 16; i++) {
        f[2 * i] = get_little_end_64(r + i * 16);
        f[2 * i + 1] = get_little_end_64(r + i * 16 + 8);
    }

    f[0] += f[4] + 2 * (f[0] & UINT32_MAX) * (f[4] & UINT32_MAX);
    f[12] = ((f[12] ^ f[0]) >> 32) | ((f[12] ^ f[0]) << 32);
    f[8] += f[12] + 2 * (f[8] & UINT32_MAX) * (f[12] & UINT32_MAX);
    f[4] = ((f[4] ^ f[8]) >> 24) | ((f[4] ^ f[8]) << 40);
    f[0] += f[4] + 2 * (f[0] & UINT32_MAX) * (f[4] & UINT32_MAX);
    f[12] = ((f[12] ^ f[0]) >> 16) | ((f[12] ^ f[0]) << 48);
    f[8] += f[12] + 2 * (f[8] & UINT32_MAX) * (f[12] & UINT32_MAX);
    f[4] = ((f[4] ^ f[8]) >> 63) | ((f[4] ^ f[8]) << 1);
    f[1] += f[5] + 2 * (f[1] & UINT32_MAX) * (f[5] & UINT32_MAX);
    f[13] = ((f[13] ^ f[1]) >> 32) | ((f[13] ^ f[1]) << 32);
    f[9] += f[13] + 2 * (f[9] & UINT32_MAX) * (f[13] & UINT32_MAX);
    f[5] = ((f[5] ^ f[9]) >> 24) | ((f[5] ^ f[9]) << 40);
    f[1] += f[5] + 2 * (f[1] & UINT32_MAX) * (f[5] & UINT32_MAX);
    f[13] = ((f[13] ^ f[1]) >> 16) | ((f[13] ^ f[1]) << 48);
    f[9] += f[13] + 2 * (f[9] & UINT32_MAX) * (f[13] & UINT32_MAX);
    f[5] = ((f[5] ^ f[9]) >> 63) | ((f[5] ^ f[9]) << 1);
    f[2] += f[6] + 2 * (f[2] & UINT32_MAX) * (f[6] & UINT32_MAX);
    f[14] = ((f[14] ^ f[2]) >> 32) | ((f[14] ^ f[2]) << 32);
    f[10] += f[14] + 2 * (f[10] & UINT32_MAX) * (f[14] & UINT32_MAX);
    f[6] = ((f[6] ^ f[10]) >> 24) | ((f[6] ^ f[10]) << 40);
    f[2] += f[6] + 2 * (f[2] & UINT32_MAX) * (f[6] & UINT32_MAX);
    f[14] = ((f[14] ^ f[2]) >> 16) | ((f[14] ^ f[2]) << 48);
    f[10] += f[14] + 2 * (f[10] & UINT32_MAX) * (f[14] & UINT32_MAX);
    f[6] = ((f[6] ^ f[10]) >> 63) | ((f[6] ^ f[10]) << 1);
    f[3] += f[7] + 2 * (f[3] & UINT32_MAX) * (f[7] & UINT32_MAX);
    f[15] = ((f[15] ^ f[3]) >> 32) | ((f[15] ^ f[3]) << 32);
    f[11] += f[15] + 2 * (f[11] & UINT32_MAX) * (f[15] & UINT32_MAX);
    f[7] = ((f[7] ^ f[11]) >> 24) | ((f[7] ^ f[11]) << 40);
    f[3] += f[7] + 2 * (f[3] & UINT32_MAX) * (f[7] & UINT32_MAX);
    f[15] = ((f[15] ^ f[3]) >> 16) | ((f[15] ^ f[3]) << 48);
    f[11] += f[15] + 2 * (f[11] & UINT32_MAX) * (f[15] & UINT32_MAX);
    f[7] = ((f[7] ^ f[11]) >> 63) | ((f[7] ^ f[11]) << 1);
    f[0] += f[5] + 2 * (f[0] & UINT32_MAX) * (f[5] & UINT32_MAX);
    f[15] = ((f[15] ^ f[0]) >> 32) | ((f[15] ^ f[0]) << 32);
    f[10] += f[15] + 2 * (f[10] & UINT32_MAX) * (f[15] & UINT32_MAX);
    f[5] = ((f[5] ^ f[10]) >> 24) | ((f[5] ^ f[10]) << 40);
    f[0] += f[5] + 2 * (f[0] & UINT32_MAX) * (f[5] & UINT32_MAX);
    f[15] = ((f[15] ^ f[0]) >> 16) | ((f[15] ^ f[0]) << 48);
    f[10] += f[15] + 2 * (f[10] & UINT32_MAX) * (f[15] & UINT32_MAX);
    f[5] = ((f[5] ^ f[10]) >> 63) | ((f[5] ^ f[10]) << 1);
    f[1] += f[6] + 2 * (f[1] & UINT32_MAX) * (f[6] & UINT32_MAX);
    f[12] = ((f[12] ^ f[1]) >> 32) | ((f[12] ^ f[1]) << 32);
    f[11] += f[12] + 2 * (f[11] & UINT32_MAX) * (f[12] & UINT32_MAX);
    f[6] = ((f[6] ^ f[11]) >> 24) | ((f[6] ^ f[11]) << 40);
    f[1] += f[6] + 2 * (f[1] & UINT32_MAX) * (f[6] & UINT32_MAX);
    f[12] = ((f[12] ^ f[1]) >> 16) | ((f[12] ^ f[1]) << 48);
    f[11] += f[12] + 2 * (f[11] & UINT32_MAX) * (f[12] & UINT32_MAX);
    f[6] = ((f[6] ^ f[11]) >> 63) | ((f[6] ^ f[11]) << 1);
    f[2] += f[7] + 2 * (f[2] & UINT32_MAX) * (f[7] & UINT32_MAX);
    f[13] = ((f[13] ^ f[2]) >> 32) | ((f[13] ^ f[2]) << 32);
    f[8] += f[13] + 2 * (f[8] & UINT32_MAX) * (f[13] & UINT32_MAX);
    f[7] = ((f[7] ^ f[8]) >> 24) | ((f[7] ^ f[8]) << 40);
    f[2] += f[7] + 2 * (f[2] & UINT32_MAX) * (f[7] & UINT32_MAX);
    f[13] = ((f[13] ^ f[2]) >> 16) | ((f[13] ^ f[2]) << 48);
    f[8] += f[13] + 2 * (f[8] & UINT32_MAX) * (f[13] & UINT32_MAX);
    f[7] = ((f[7] ^ f[8]) >> 63) | ((f[7] ^ f[8]) << 1);
    f[3] += f[4] + 2 * (f[3] & UINT32_MAX) * (f[4] & UINT32_MAX);
    f[14] = ((f[14] ^ f[3]) >> 32) | ((f[14] ^ f[3]) << 32);
    f[9] += f[14] + 2 * (f[9] & UINT32_MAX) * (f[14] & UINT32_MAX);
    f[4] = ((f[4] ^ f[9]) >> 24) | ((f[4] ^ f[9]) << 40);
    f[3] += f[4] + 2 * (f[3] & UINT32_MAX) * (f[4] & UINT32_MAX);
    f[14] = ((f[14] ^ f[3]) >> 16) | ((f[14] ^ f[3]) << 48);
    f[9] += f[14] + 2 * (f[9] & UINT32_MAX) * (f[14] & UINT32_MAX);
    f[4] = ((f[4] ^ f[9]) >> 63) | ((f[4] ^ f[9]) << 1);
    f[16] += f[20] + 2 * (f[16] & UINT32_MAX) * (f[20] & UINT32_MAX);
    f[28] = ((f[28] ^ f[16]) >> 32) | ((f[28] ^ f[16]) << 32);
    f[24] += f[28] + 2 * (f[24] & UINT32_MAX) * (f[28] & UINT32_MAX);
    f[20] = ((f[20] ^ f[24]) >> 24) | ((f[20] ^ f[24]) << 40);
    f[16] += f[20] + 2 * (f[16] & UINT32_MAX) * (f[20] & UINT32_MAX);
    f[28] = ((f[28] ^ f[16]) >> 16) | ((f[28] ^ f[16]) << 48);
    f[24] += f[28] + 2 * (f[24] & UINT32_MAX) * (f[28] & UINT32_MAX);
    f[20] = ((f[20] ^ f[24]) >> 63) | ((f[20] ^ f[24]) << 1);
    f[17] += f[21] + 2 * (f[17] & UINT32_MAX) * (f[21] & UINT32_MAX);
    f[29] = ((f[29] ^ f[17]) >> 32) | ((f[29] ^ f[17]) << 32);
    f[25] += f[29] + 2 * (f[25] & UINT32_MAX) * (f[29] & UINT32_MAX);
    f[21] = ((f[21] ^ f[25]) >> 24) | ((f[21] ^ f[25]) << 40);
    f[17] += f[21] + 2 * (f[17] & UINT32_MAX) * (f[21] & UINT32_MAX);
    f[29] = ((f[29] ^ f[17]) >> 16) | ((f[29] ^ f[17]) << 48);
    f[25] += f[29] + 2 * (f[25] & UINT32_MAX) * (f[29] & UINT32_MAX);
    f[21] = ((f[21] ^ f[25]) >> 63) | ((f[21] ^ f[25]) << 1);
    f[18] += f[22] + 2 * (f[18] & UINT32_MAX) * (f[22] & UINT32_MAX);
    f[30] = ((f[30] ^ f[18]) >> 32) | ((f[30] ^ f[18]) << 32);
    f[26] += f[30] + 2 * (f[26] & UINT32_MAX) * (f[30] & UINT32_MAX);
    f[22] = ((f[22] ^ f[26]) >> 24) | ((f[22] ^ f[26]) << 40);
    f[18] += f[22] + 2 * (f[18] & UINT32_MAX) * (f[22] & UINT32_MAX);
    f[30] = ((f[30] ^ f[18]) >> 16) | ((f[30] ^ f[18]) << 48);
    f[26] += f[30] + 2 * (f[26] & UINT32_MAX) * (f[30] & UINT32_MAX);
    f[22] = ((f[22] ^ f[26]) >> 63) | ((f[22] ^ f[26]) << 1);
    f[19] += f[23] + 2 * (f[19] & UINT32_MAX) * (f[23] & UINT32_MAX);
    f[31] = ((f[31] ^ f[19]) >> 32) | ((f[31] ^ f[19]) << 32);
    f[27] += f[31] + 2 * (f[27] & UINT32_MAX) * (f[31] & UINT32_MAX);
    f[23] = ((f[23] ^ f[27]) >> 24) | ((f[23] ^ f[27]) << 40);
    f[19] += f[23] + 2 * (f[19] & UINT32_MAX) * (f[23] & UINT32_MAX);
    f[31] = ((f[31] ^ f[19]) >> 16) | ((f[31] ^ f[19]) << 48);
    f[27] += f[31] + 2 * (f[27] & UINT32_MAX) * (f[31] & UINT32_MAX);
    f[23] = ((f[23] ^ f[27]) >> 63) | ((f[23] ^ f[27]) << 1);
    f[16] += f[21] + 2 * (f[16] & UINT32_MAX) * (f[21] & UINT32_MAX);
    f[31] = ((f[31] ^ f[16]) >> 32) | ((f[31] ^ f[16]) << 32);
    f[26] += f[31] + 2 * (f[26] & UINT32_MAX) * (f[31] & UINT32_MAX);
    f[21] = ((f[21] ^ f[26]) >> 24) | ((f[21] ^ f[26]) << 40);
    f[16] += f[21] + 2 * (f[16] & UINT32_MAX) * (f[21] & UINT32_MAX);
    f[31] = ((f[31] ^ f[16]) >> 16) | ((f[31] ^ f[16]) << 48);
    f[26] += f[31] + 2 * (f[26] & UINT32_MAX) * (f[31] & UINT32_MAX);
    f[21] = ((f[21] ^ f[26]) >> 63) | ((f[21] ^ f[26]) << 1);
    f[17] += f[22] + 2 * (f[17] & UINT32_MAX) * (f[22] & UINT32_MAX);
    f[28] = ((f[28] ^ f[17]) >> 32) | ((f[28] ^ f[17]) << 32);
    f[27] += f[28] + 2 * (f[27] & UINT32_MAX) * (f[28] & UINT32_MAX);
    f[22] = ((f[22] ^ f[27]) >> 24) | ((f[22] ^ f[27]) << 40);
    f[17] += f[22] + 2 * (f[17] & UINT32_MAX) * (f[22] & UINT32_MAX);
    f[28] = ((f[28] ^ f[17]) >> 16) | ((f[28] ^ f[17]) << 48);
    f[27] += f[28] + 2 * (f[27] & UINT32_MAX) * (f[28] & UINT32_MAX);
    f[22] = ((f[22] ^ f[27]) >> 63) | ((f[22] ^ f[27]) << 1);
    f[18] += f[23] + 2 * (f[18] & UINT32_MAX) * (f[23] & UINT32_MAX);
    f[29] = ((f[29] ^ f[18]) >> 32) | ((f[29] ^ f[18]) << 32);
    f[24] += f[29] + 2 * (f[24] & UINT32_MAX) * (f[29] & UINT32_MAX);
    f[23] = ((f[23] ^ f[24]) >> 24) | ((f[23] ^ f[24]) << 40);
    f[18] += f[23] + 2 * (f[18] & UINT32_MAX) * (f[23] & UINT32_MAX);
    f[29] = ((f[29] ^ f[18]) >> 16) | ((f[29] ^ f[18]) << 48);
    f[24] += f[29] + 2 * (f[24] & UINT32_MAX) * (f[29] & UINT32_MAX);
    f[23] = ((f[23] ^ f[24]) >> 63) | ((f[23] ^ f[24]) << 1);
    f[19] += f[20] + 2 * (f[19] & UINT32_MAX) * (f[20] & UINT32_MAX);
    f[30] = ((f[30] ^ f[19]) >> 32) | ((f[30] ^ f[19]) << 32);
    f[25] += f[30] + 2 * (f[25] & UINT32_MAX) * (f[30] & UINT32_MAX);
    f[20] = ((f[20] ^ f[25]) >> 24) | ((f[20] ^ f[25]) << 40);
    f[19] += f[20] + 2 * (f[19] & UINT32_MAX) * (f[20] & UINT32_MAX);
    f[30] = ((f[30] ^ f[19]) >> 16) | ((f[30] ^ f[19]) << 48);
    f[25] += f[30] + 2 * (f[25] & UINT32_MAX) * (f[30] & UINT32_MAX);
    f[20] = ((f[20] ^ f[25]) >> 63) | ((f[20] ^ f[25]) << 1);
    f[32] += f[36] + 2 * (f[32] & UINT32_MAX) * (f[36] & UINT32_MAX);
    f[44] = ((f[44] ^ f[32]) >> 32) | ((f[44] ^ f[32]) << 32);
    f[40] += f[44] + 2 * (f[40] & UINT32_MAX) * (f[44] & UINT32_MAX);
    f[36] = ((f[36] ^ f[40]) >> 24) | ((f[36] ^ f[40]) << 40);
    f[32] += f[36] + 2 * (f[32] & UINT32_MAX) * (f[36] & UINT32_MAX);
    f[44] = ((f[44] ^ f[32]) >> 16) | ((f[44] ^ f[32]) << 48);
    f[40] += f[44] + 2 * (f[40] & UINT32_MAX) * (f[44] & UINT32_MAX);
    f[36] = ((f[36] ^ f[40]) >> 63) | ((f[36] ^ f[40]) << 1);
    f[33] += f[37] + 2 * (f[33] & UINT32_MAX) * (f[37] & UINT32_MAX);
    f[45] = ((f[45] ^ f[33]) >> 32) | ((f[45] ^ f[33]) << 32);
    f[41] += f[45] + 2 * (f[41] & UINT32_MAX) * (f[45] & UINT32_MAX);
    f[37] = ((f[37] ^ f[41]) >> 24) | ((f[37] ^ f[41]) << 40);
    f[33] += f[37] + 2 * (f[33] & UINT32_MAX) * (f[37] & UINT32_MAX);
    f[45] = ((f[45] ^ f[33]) >> 16) | ((f[45] ^ f[33]) << 48);
    f[41] += f[45] + 2 * (f[41] & UINT32_MAX) * (f[45] & UINT32_MAX);
    f[37] = ((f[37] ^ f[41]) >> 63) | ((f[37] ^ f[41]) << 1);
    f[34] += f[38] + 2 * (f[34] & UINT32_MAX) * (f[38] & UINT32_MAX);
    f[46] = ((f[46] ^ f[34]) >> 32) | ((f[46] ^ f[34]) << 32);
    f[42] += f[46] + 2 * (f[42] & UINT32_MAX) * (f[46] & UINT32_MAX);
    f[38] = ((f[38] ^ f[42]) >> 24) | ((f[38] ^ f[42]) << 40);
    f[34] += f[38] + 2 * (f[34] & UINT32_MAX) * (f[38] & UINT32_MAX);
    f[46] = ((f[46] ^ f[34]) >> 16) | ((f[46] ^ f[34]) << 48);
    f[42] += f[46] + 2 * (f[42] & UINT32_MAX) * (f[46] & UINT32_MAX);
    f[38] = ((f[38] ^ f[42]) >> 63) | ((f[38] ^ f[42]) << 1);
    f[35] += f[39] + 2 * (f[35] & UINT32_MAX) * (f[39] & UINT32_MAX);
    f[47] = ((f[47] ^ f[35]) >> 32) | ((f[47] ^ f[35]) << 32);
    f[43] += f[47] + 2 * (f[43] & UINT32_MAX) * (f[47] & UINT32_MAX);
    f[39] = ((f[39] ^ f[43]) >> 24) | ((f[39] ^ f[43]) << 40);
    f[35] += f[39] + 2 * (f[35] & UINT32_MAX) * (f[39] & UINT32_MAX);
    f[47] = ((f[47] ^ f[35]) >> 16) | ((f[47] ^ f[35]) << 48);
    f[43] += f[47] + 2 * (f[43] & UINT32_MAX) * (f[47] & UINT32_MAX);
    f[39] = ((f[39] ^ f[43]) >> 63) | ((f[39] ^ f[43]) << 1);
    f[32] += f[37] + 2 * (f[32] & UINT32_MAX) * (f[37] & UINT32_MAX);
    f[47] = ((f[47] ^ f[32]) >> 32) | ((f[47] ^ f[32]) << 32);
    f[42] += f[47] + 2 * (f[42] & UINT32_MAX) * (f[47] & UINT32_MAX);
    f[37] = ((f[37] ^ f[42]) >> 24) | ((f[37] ^ f[42]) << 40);
    f[32] += f[37] + 2 * (f[32] & UINT32_MAX) * (f[37] & UINT32_MAX);
    f[47] = ((f[47] ^ f[32]) >> 16) | ((f[47] ^ f[32]) << 48);
    f[42] += f[47] + 2 * (f[42] & UINT32_MAX) * (f[47] & UINT32_MAX);
    f[37] = ((f[37] ^ f[42]) >> 63) | ((f[37] ^ f[42]) << 1);
    f[33] += f[38] + 2 * (f[33] & UINT32_MAX) * (f[38] & UINT32_MAX);
    f[44] = ((f[44] ^ f[33]) >> 32) | ((f[44] ^ f[33]) << 32);
    f[43] += f[44] + 2 * (f[43] & UINT32_MAX) * (f[44] & UINT32_MAX);
    f[38] = ((f[38] ^ f[43]) >> 24) | ((f[38] ^ f[43]) << 40);
    f[33] += f[38] + 2 * (f[33] & UINT32_MAX) * (f[38] & UINT32_MAX);
    f[44] = ((f[44] ^ f[33]) >> 16) | ((f[44] ^ f[33]) << 48);
    f[43] += f[44] + 2 * (f[43] & UINT32_MAX) * (f[44] & UINT32_MAX);
    f[38] = ((f[38] ^ f[43]) >> 63) | ((f[38] ^ f[43]) << 1);
    f[34] += f[39] + 2 * (f[34] & UINT32_MAX) * (f[39] & UINT32_MAX);
    f[45] = ((f[45] ^ f[34]) >> 32) | ((f[45] ^ f[34]) << 32);
    f[40] += f[45] + 2 * (f[40] & UINT32_MAX) * (f[45] & UINT32_MAX);
    f[39] = ((f[39] ^ f[40]) >> 24) | ((f[39] ^ f[40]) << 40);
    f[34] += f[39] + 2 * (f[34] & UINT32_MAX) * (f[39] & UINT32_MAX);
    f[45] = ((f[45] ^ f[34]) >> 16) | ((f[45] ^ f[34]) << 48);
    f[40] += f[45] + 2 * (f[40] & UINT32_MAX) * (f[45] & UINT32_MAX);
    f[39] = ((f[39] ^ f[40]) >> 63) | ((f[39] ^ f[40]) << 1);
    f[35] += f[36] + 2 * (f[35] & UINT32_MAX) * (f[36] & UINT32_MAX);
    f[46] = ((f[46] ^ f[35]) >> 32) | ((f[46] ^ f[35]) << 32);
    f[41] += f[46] + 2 * (f[41] & UINT32_MAX) * (f[46] & UINT32_MAX);
    f[36] = ((f[36] ^ f[41]) >> 24) | ((f[36] ^ f[41]) << 40);
    f[35] += f[36] + 2 * (f[35] & UINT32_MAX) * (f[36] & UINT32_MAX);
    f[46] = ((f[46] ^ f[35]) >> 16) | ((f[46] ^ f[35]) << 48);
    f[41] += f[46] + 2 * (f[41] & UINT32_MAX) * (f[46] & UINT32_MAX);
    f[36] = ((f[36] ^ f[41]) >> 63) | ((f[36] ^ f[41]) << 1);
    f[48] += f[52] + 2 * (f[48] & UINT32_MAX) * (f[52] & UINT32_MAX);
    f[60] = ((f[60] ^ f[48]) >> 32) | ((f[60] ^ f[48]) << 32);
    f[56] += f[60] + 2 * (f[56] & UINT32_MAX) * (f[60] & UINT32_MAX);
    f[52] = ((f[52] ^ f[56]) >> 24) | ((f[52] ^ f[56]) << 40);
    f[48] += f[52] + 2 * (f[48] & UINT32_MAX) * (f[52] & UINT32_MAX);
    f[60] = ((f[60] ^ f[48]) >> 16) | ((f[60] ^ f[48]) << 48);
    f[56] += f[60] + 2 * (f[56] & UINT32_MAX) * (f[60] & UINT32_MAX);
    f[52] = ((f[52] ^ f[56]) >> 63) | ((f[52] ^ f[56]) << 1);
    f[49] += f[53] + 2 * (f[49] & UINT32_MAX) * (f[53] & UINT32_MAX);
    f[61] = ((f[61] ^ f[49]) >> 32) | ((f[61] ^ f[49]) << 32);
    f[57] += f[61] + 2 * (f[57] & UINT32_MAX) * (f[61] & UINT32_MAX);
    f[53] = ((f[53] ^ f[57]) >> 24) | ((f[53] ^ f[57]) << 40);
    f[49] += f[53] + 2 * (f[49] & UINT32_MAX) * (f[53] & UINT32_MAX);
    f[61] = ((f[61] ^ f[49]) >> 16) | ((f[61] ^ f[49]) << 48);
    f[57] += f[61] + 2 * (f[57] & UINT32_MAX) * (f[61] & UINT32_MAX);
    f[53] = ((f[53] ^ f[57]) >> 63) | ((f[53] ^ f[57]) << 1);
    f[50] += f[54] + 2 * (f[50] & UINT32_MAX) * (f[54] & UINT32_MAX);
    f[62] = ((f[62] ^ f[50]) >> 32) | ((f[62] ^ f[50]) << 32);
    f[58] += f[62] + 2 * (f[58] & UINT32_MAX) * (f[62] & UINT32_MAX);
    f[54] = ((f[54] ^ f[58]) >> 24) | ((f[54] ^ f[58]) << 40);
    f[50] += f[54] + 2 * (f[50] & UINT32_MAX) * (f[54] & UINT32_MAX);
    f[62] = ((f[62] ^ f[50]) >> 16) | ((f[62] ^ f[50]) << 48);
    f[58] += f[62] + 2 * (f[58] & UINT32_MAX) * (f[62] & UINT32_MAX);
    f[54] = ((f[54] ^ f[58]) >> 63) | ((f[54] ^ f[58]) << 1);
    f[51] += f[55] + 2 * (f[51] & UINT32_MAX) * (f[55] & UINT32_MAX);
    f[63] = ((f[63] ^ f[51]) >> 32) | ((f[63] ^ f[51]) << 32);
    f[59] += f[63] + 2 * (f[59] & UINT32_MAX) * (f[63] & UINT32_MAX);
    f[55] = ((f[55] ^ f[59]) >> 24) | ((f[55] ^ f[59]) << 40);
    f[51] += f[55] + 2 * (f[51] & UINT32_MAX) * (f[55] & UINT32_MAX);
    f[63] = ((f[63] ^ f[51]) >> 16) | ((f[63] ^ f[51]) << 48);
    f[59] += f[63] + 2 * (f[59] & UINT32_MAX) * (f[63] & UINT32_MAX);
    f[55] = ((f[55] ^ f[59]) >> 63) | ((f[55] ^ f[59]) << 1);
    f[48] += f[53] + 2 * (f[48] & UINT32_MAX) * (f[53] & UINT32_MAX);
    f[63] = ((f[63] ^ f[48]) >> 32) | ((f[63] ^ f[48]) << 32);
    f[58] += f[63] + 2 * (f[58] & UINT32_MAX) * (f[63] & UINT32_MAX);
    f[53] = ((f[53] ^ f[58]) >> 24) | ((f[53] ^ f[58]) << 40);
    f[48] += f[53] + 2 * (f[48] & UINT32_MAX) * (f[53] & UINT32_MAX);
    f[63] = ((f[63] ^ f[48]) >> 16) | ((f[63] ^ f[48]) << 48);
    f[58] += f[63] + 2 * (f[58] & UINT32_MAX) * (f[63] & UINT32_MAX);
    f[53] = ((f[53] ^ f[58]) >> 63) | ((f[53] ^ f[58]) << 1);
    f[49] += f[54] + 2 * (f[49] & UINT32_MAX) * (f[54] & UINT32_MAX);
    f[60] = ((f[60] ^ f[49]) >> 32) | ((f[60] ^ f[49]) << 32);
    f[59] += f[60] + 2 * (f[59] & UINT32_MAX) * (f[60] & UINT32_MAX);
    f[54] = ((f[54] ^ f[59]) >> 24) | ((f[54] ^ f[59]) << 40);
    f[49] += f[54] + 2 * (f[49] & UINT32_MAX) * (f[54] & UINT32_MAX);
    f[60] = ((f[60] ^ f[49]) >> 16) | ((f[60] ^ f[49]) << 48);
    f[59] += f[60] + 2 * (f[59] & UINT32_MAX) * (f[60] & UINT32_MAX);
    f[54] = ((f[54] ^ f[59]) >> 63) | ((f[54] ^ f[59]) << 1);
    f[50] += f[55] + 2 * (f[50] & UINT32_MAX) * (f[55] & UINT32_MAX);
    f[61] = ((f[61] ^ f[50]) >> 32) | ((f[61] ^ f[50]) << 32);
    f[56] += f[61] + 2 * (f[56] & UINT32_MAX) * (f[61] & UINT32_MAX);
    f[55] = ((f[55] ^ f[56]) >> 24) | ((f[55] ^ f[56]) << 40);
    f[50] += f[55] + 2 * (f[50] & UINT32_MAX) * (f[55] & UINT32_MAX);
    f[61] = ((f[61] ^ f[50]) >> 16) | ((f[61] ^ f[50]) << 48);
    f[56] += f[61] + 2 * (f[56] & UINT32_MAX) * (f[61] & UINT32_MAX);
    f[55] = ((f[55] ^ f[56]) >> 63) | ((f[55] ^ f[56]) << 1);
    f[51] += f[52] + 2 * (f[51] & UINT32_MAX) * (f[52] & UINT32_MAX);
    f[62] = ((f[62] ^ f[51]) >> 32) | ((f[62] ^ f[51]) << 32);
    f[57] += f[62] + 2 * (f[57] & UINT32_MAX) * (f[62] & UINT32_MAX);
    f[52] = ((f[52] ^ f[57]) >> 24) | ((f[52] ^ f[57]) << 40);
    f[51] += f[52] + 2 * (f[51] & UINT32_MAX) * (f[52] & UINT32_MAX);
    f[62] = ((f[62] ^ f[51]) >> 16) | ((f[62] ^ f[51]) << 48);
    f[57] += f[62] + 2 * (f[57] & UINT32_MAX) * (f[62] & UINT32_MAX);
    f[52] = ((f[52] ^ f[57]) >> 63) | ((f[52] ^ f[57]) << 1);
    f[64] += f[68] + 2 * (f[64] & UINT32_MAX) * (f[68] & UINT32_MAX);
    f[76] = ((f[76] ^ f[64]) >> 32) | ((f[76] ^ f[64]) << 32);
    f[72] += f[76] + 2 * (f[72] & UINT32_MAX) * (f[76] & UINT32_MAX);
    f[68] = ((f[68] ^ f[72]) >> 24) | ((f[68] ^ f[72]) << 40);
    f[64] += f[68] + 2 * (f[64] & UINT32_MAX) * (f[68] & UINT32_MAX);
    f[76] = ((f[76] ^ f[64]) >> 16) | ((f[76] ^ f[64]) << 48);
    f[72] += f[76] + 2 * (f[72] & UINT32_MAX) * (f[76] & UINT32_MAX);
    f[68] = ((f[68] ^ f[72]) >> 63) | ((f[68] ^ f[72]) << 1);
    f[65] += f[69] + 2 * (f[65] & UINT32_MAX) * (f[69] & UINT32_MAX);
    f[77] = ((f[77] ^ f[65]) >> 32) | ((f[77] ^ f[65]) << 32);
    f[73] += f[77] + 2 * (f[73] & UINT32_MAX) * (f[77] & UINT32_MAX);
    f[69] = ((f[69] ^ f[73]) >> 24) | ((f[69] ^ f[73]) << 40);
    f[65] += f[69] + 2 * (f[65] & UINT32_MAX) * (f[69] & UINT32_MAX);
    f[77] = ((f[77] ^ f[65]) >> 16) | ((f[77] ^ f[65]) << 48);
    f[73] += f[77] + 2 * (f[73] & UINT32_MAX) * (f[77] & UINT32_MAX);
    f[69] = ((f[69] ^ f[73]) >> 63) | ((f[69] ^ f[73]) << 1);
    f[66] += f[70] + 2 * (f[66] & UINT32_MAX) * (f[70] & UINT32_MAX);
    f[78] = ((f[78] ^ f[66]) >> 32) | ((f[78] ^ f[66]) << 32);
    f[74] += f[78] + 2 * (f[74] & UINT32_MAX) * (f[78] & UINT32_MAX);
    f[70] = ((f[70] ^ f[74]) >> 24) | ((f[70] ^ f[74]) << 40);
    f[66] += f[70] + 2 * (f[66] & UINT32_MAX) * (f[70] & UINT32_MAX);
    f[78] = ((f[78] ^ f[66]) >> 16) | ((f[78] ^ f[66]) << 48);
    f[74] += f[78] + 2 * (f[74] & UINT32_MAX) * (f[78] & UINT32_MAX);
    f[70] = ((f[70] ^ f[74]) >> 63) | ((f[70] ^ f[74]) << 1);
    f[67] += f[71] + 2 * (f[67] & UINT32_MAX) * (f[71] & UINT32_MAX);
    f[79] = ((f[79] ^ f[67]) >> 32) | ((f[79] ^ f[67]) << 32);
    f[75] += f[79] + 2 * (f[75] & UINT32_MAX) * (f[79] & UINT32_MAX);
    f[71] = ((f[71] ^ f[75]) >> 24) | ((f[71] ^ f[75]) << 40);
    f[67] += f[71] + 2 * (f[67] & UINT32_MAX) * (f[71] & UINT32_MAX);
    f[79] = ((f[79] ^ f[67]) >> 16) | ((f[79] ^ f[67]) << 48);
    f[75] += f[79] + 2 * (f[75] & UINT32_MAX) * (f[79] & UINT32_MAX);
    f[71] = ((f[71] ^ f[75]) >> 63) | ((f[71] ^ f[75]) << 1);
    f[64] += f[69] + 2 * (f[64] & UINT32_MAX) * (f[69] & UINT32_MAX);
    f[79] = ((f[79] ^ f[64]) >> 32) | ((f[79] ^ f[64]) << 32);
    f[74] += f[79] + 2 * (f[74] & UINT32_MAX) * (f[79] & UINT32_MAX);
    f[69] = ((f[69] ^ f[74]) >> 24) | ((f[69] ^ f[74]) << 40);
    f[64] += f[69] + 2 * (f[64] & UINT32_MAX) * (f[69] & UINT32_MAX);
    f[79] = ((f[79] ^ f[64]) >> 16) | ((f[79] ^ f[64]) << 48);
    f[74] += f[79] + 2 * (f[74] & UINT32_MAX) * (f[79] & UINT32_MAX);
    f[69] = ((f[69] ^ f[74]) >> 63) | ((f[69] ^ f[74]) << 1);
    f[65] += f[70] + 2 * (f[65] & UINT32_MAX) * (f[70] & UINT32_MAX);
    f[76] = ((f[76] ^ f[65]) >> 32) | ((f[76] ^ f[65]) << 32);
    f[75] += f[76] + 2 * (f[75] & UINT32_MAX) * (f[76] & UINT32_MAX);
    f[70] = ((f[70] ^ f[75]) >> 24) | ((f[70] ^ f[75]) << 40);
    f[65] += f[70] + 2 * (f[65] & UINT32_MAX) * (f[70] & UINT32_MAX);
    f[76] = ((f[76] ^ f[65]) >> 16) | ((f[76] ^ f[65]) << 48);
    f[75] += f[76] + 2 * (f[75] & UINT32_MAX) * (f[76] & UINT32_MAX);
    f[70] = ((f[70] ^ f[75]) >> 63) | ((f[70] ^ f[75]) << 1);
    f[66] += f[71] + 2 * (f[66] & UINT32_MAX) * (f[71] & UINT32_MAX);
    f[77] = ((f[77] ^ f[66]) >> 32) | ((f[77] ^ f[66]) << 32);
    f[72] += f[77] + 2 * (f[72] & UINT32_MAX) * (f[77] & UINT32_MAX);
    f[71] = ((f[71] ^ f[72]) >> 24) | ((f[71] ^ f[72]) << 40);
    f[66] += f[71] + 2 * (f[66] & UINT32_MAX) * (f[71] & UINT32_MAX);
    f[77] = ((f[77] ^ f[66]) >> 16) | ((f[77] ^ f[66]) << 48);
    f[72] += f[77] + 2 * (f[72] & UINT32_MAX) * (f[77] & UINT32_MAX);
    f[71] = ((f[71] ^ f[72]) >> 63) | ((f[71] ^ f[72]) << 1);
    f[67] += f[68] + 2 * (f[67] & UINT32_MAX) * (f[68] & UINT32_MAX);
    f[78] = ((f[78] ^ f[67]) >> 32) | ((f[78] ^ f[67]) << 32);
    f[73] += f[78] + 2 * (f[73] & UINT32_MAX) * (f[78] & UINT32_MAX);
    f[68] = ((f[68] ^ f[73]) >> 24) | ((f[68] ^ f[73]) << 40);
    f[67] += f[68] + 2 * (f[67] & UINT32_MAX) * (f[68] & UINT32_MAX);
    f[78] = ((f[78] ^ f[67]) >> 16) | ((f[78] ^ f[67]) << 48);
    f[73] += f[78] + 2 * (f[73] & UINT32_MAX) * (f[78] & UINT32_MAX);
    f[68] = ((f[68] ^ f[73]) >> 63) | ((f[68] ^ f[73]) << 1);
    f[80] += f[84] + 2 * (f[80] & UINT32_MAX) * (f[84] & UINT32_MAX);
    f[92] = ((f[92] ^ f[80]) >> 32) | ((f[92] ^ f[80]) << 32);
    f[88] += f[92] + 2 * (f[88] & UINT32_MAX) * (f[92] & UINT32_MAX);
    f[84] = ((f[84] ^ f[88]) >> 24) | ((f[84] ^ f[88]) << 40);
    f[80] += f[84] + 2 * (f[80] & UINT32_MAX) * (f[84] & UINT32_MAX);
    f[92] = ((f[92] ^ f[80]) >> 16) | ((f[92] ^ f[80]) << 48);
    f[88] += f[92] + 2 * (f[88] & UINT32_MAX) * (f[92] & UINT32_MAX);
    f[84] = ((f[84] ^ f[88]) >> 63) | ((f[84] ^ f[88]) << 1);
    f[81] += f[85] + 2 * (f[81] & UINT32_MAX) * (f[85] & UINT32_MAX);
    f[93] = ((f[93] ^ f[81]) >> 32) | ((f[93] ^ f[81]) << 32);
    f[89] += f[93] + 2 * (f[89] & UINT32_MAX) * (f[93] & UINT32_MAX);
    f[85] = ((f[85] ^ f[89]) >> 24) | ((f[85] ^ f[89]) << 40);
    f[81] += f[85] + 2 * (f[81] & UINT32_MAX) * (f[85] & UINT32_MAX);
    f[93] = ((f[93] ^ f[81]) >> 16) | ((f[93] ^ f[81]) << 48);
    f[89] += f[93] + 2 * (f[89] & UINT32_MAX) * (f[93] & UINT32_MAX);
    f[85] = ((f[85] ^ f[89]) >> 63) | ((f[85] ^ f[89]) << 1);
    f[82] += f[86] + 2 * (f[82] & UINT32_MAX) * (f[86] & UINT32_MAX);
    f[94] = ((f[94] ^ f[82]) >> 32) | ((f[94] ^ f[82]) << 32);
    f[90] += f[94] + 2 * (f[90] & UINT32_MAX) * (f[94] & UINT32_MAX);
    f[86] = ((f[86] ^ f[90]) >> 24) | ((f[86] ^ f[90]) << 40);
    f[82] += f[86] + 2 * (f[82] & UINT32_MAX) * (f[86] & UINT32_MAX);
    f[94] = ((f[94] ^ f[82]) >> 16) | ((f[94] ^ f[82]) << 48);
    f[90] += f[94] + 2 * (f[90] & UINT32_MAX) * (f[94] & UINT32_MAX);
    f[86] = ((f[86] ^ f[90]) >> 63) | ((f[86] ^ f[90]) << 1);
    f[83] += f[87] + 2 * (f[83] & UINT32_MAX) * (f[87] & UINT32_MAX);
    f[95] = ((f[95] ^ f[83]) >> 32) | ((f[95] ^ f[83]) << 32);
    f[91] += f[95] + 2 * (f[91] & UINT32_MAX) * (f[95] & UINT32_MAX);
    f[87] = ((f[87] ^ f[91]) >> 24) | ((f[87] ^ f[91]) << 40);
    f[83] += f[87] + 2 * (f[83] & UINT32_MAX) * (f[87] & UINT32_MAX);
    f[95] = ((f[95] ^ f[83]) >> 16) | ((f[95] ^ f[83]) << 48);
    f[91] += f[95] + 2 * (f[91] & UINT32_MAX) * (f[95] & UINT32_MAX);
    f[87] = ((f[87] ^ f[91]) >> 63) | ((f[87] ^ f[91]) << 1);
    f[80] += f[85] + 2 * (f[80] & UINT32_MAX) * (f[85] & UINT32_MAX);
    f[95] = ((f[95] ^ f[80]) >> 32) | ((f[95] ^ f[80]) << 32);
    f[90] += f[95] + 2 * (f[90] & UINT32_MAX) * (f[95] & UINT32_MAX);
    f[85] = ((f[85] ^ f[90]) >> 24) | ((f[85] ^ f[90]) << 40);
    f[80] += f[85] + 2 * (f[80] & UINT32_MAX) * (f[85] & UINT32_MAX);
    f[95] = ((f[95] ^ f[80]) >> 16) | ((f[95] ^ f[80]) << 48);
    f[90] += f[95] + 2 * (f[90] & UINT32_MAX) * (f[95] & UINT32_MAX);
    f[85] = ((f[85] ^ f[90]) >> 63) | ((f[85] ^ f[90]) << 1);
    f[81] += f[86] + 2 * (f[81] & UINT32_MAX) * (f[86] & UINT32_MAX);
    f[92] = ((f[92] ^ f[81]) >> 32) | ((f[92] ^ f[81]) << 32);
    f[91] += f[92] + 2 * (f[91] & UINT32_MAX) * (f[92] & UINT32_MAX);
    f[86] = ((f[86] ^ f[91]) >> 24) | ((f[86] ^ f[91]) << 40);
    f[81] += f[86] + 2 * (f[81] & UINT32_MAX) * (f[86] & UINT32_MAX);
    f[92] = ((f[92] ^ f[81]) >> 16) | ((f[92] ^ f[81]) << 48);
    f[91] += f[92] + 2 * (f[91] & UINT32_MAX) * (f[92] & UINT32_MAX);
    f[86] = ((f[86] ^ f[91]) >> 63) | ((f[86] ^ f[91]) << 1);
    f[82] += f[87] + 2 * (f[82] & UINT32_MAX) * (f[87] & UINT32_MAX);
    f[93] = ((f[93] ^ f[82]) >> 32) | ((f[93] ^ f[82]) << 32);
    f[88] += f[93] + 2 * (f[88] & UINT32_MAX) * (f[93] & UINT32_MAX);
    f[87] = ((f[87] ^ f[88]) >> 24) | ((f[87] ^ f[88]) << 40);
    f[82] += f[87] + 2 * (f[82] & UINT32_MAX) * (f[87] & UINT32_MAX);
    f[93] = ((f[93] ^ f[82]) >> 16) | ((f[93] ^ f[82]) << 48);
    f[88] += f[93] + 2 * (f[88] & UINT32_MAX) * (f[93] & UINT32_MAX);
    f[87] = ((f[87] ^ f[88]) >> 63) | ((f[87] ^ f[88]) << 1);
    f[83] += f[84] + 2 * (f[83] & UINT32_MAX) * (f[84] & UINT32_MAX);
    f[94] = ((f[94] ^ f[83]) >> 32) | ((f[94] ^ f[83]) << 32);
    f[89] += f[94] + 2 * (f[89] & UINT32_MAX) * (f[94] & UINT32_MAX);
    f[84] = ((f[84] ^ f[89]) >> 24) | ((f[84] ^ f[89]) << 40);
    f[83] += f[84] + 2 * (f[83] & UINT32_MAX) * (f[84] & UINT32_MAX);
    f[94] = ((f[94] ^ f[83]) >> 16) | ((f[94] ^ f[83]) << 48);
    f[89] += f[94] + 2 * (f[89] & UINT32_MAX) * (f[94] & UINT32_MAX);
    f[84] = ((f[84] ^ f[89]) >> 63) | ((f[84] ^ f[89]) << 1);
    f[96] += f[100] + 2 * (f[96] & UINT32_MAX) * (f[100] & UINT32_MAX);
    f[108] = ((f[108] ^ f[96]) >> 32) | ((f[108] ^ f[96]) << 32);
    f[104] += f[108] + 2 * (f[104] & UINT32_MAX) * (f[108] & UINT32_MAX);
    f[100] = ((f[100] ^ f[104]) >> 24) | ((f[100] ^ f[104]) << 40);
    f[96] += f[100] + 2 * (f[96] & UINT32_MAX) * (f[100] & UINT32_MAX);
    f[108] = ((f[108] ^ f[96]) >> 16) | ((f[108] ^ f[96]) << 48);
    f[104] += f[108] + 2 * (f[104] & UINT32_MAX) * (f[108] & UINT32_MAX);
    f[100] = ((f[100] ^ f[104]) >> 63) | ((f[100] ^ f[104]) << 1);
    f[97] += f[101] + 2 * (f[97] & UINT32_MAX) * (f[101] & UINT32_MAX);
    f[109] = ((f[109] ^ f[97]) >> 32) | ((f[109] ^ f[97]) << 32);
    f[105] += f[109] + 2 * (f[105] & UINT32_MAX) * (f[109] & UINT32_MAX);
    f[101] = ((f[101] ^ f[105]) >> 24) | ((f[101] ^ f[105]) << 40);
    f[97] += f[101] + 2 * (f[97] & UINT32_MAX) * (f[101] & UINT32_MAX);
    f[109] = ((f[109] ^ f[97]) >> 16) | ((f[109] ^ f[97]) << 48);
    f[105] += f[109] + 2 * (f[105] & UINT32_MAX) * (f[109] & UINT32_MAX);
    f[101] = ((f[101] ^ f[105]) >> 63) | ((f[101] ^ f[105]) << 1);
    f[98] += f[102] + 2 * (f[98] & UINT32_MAX) * (f[102] & UINT32_MAX);
    f[110] = ((f[110] ^ f[98]) >> 32) | ((f[110] ^ f[98]) << 32);
    f[106] += f[110] + 2 * (f[106] & UINT32_MAX) * (f[110] & UINT32_MAX);
    f[102] = ((f[102] ^ f[106]) >> 24) | ((f[102] ^ f[106]) << 40);
    f[98] += f[102] + 2 * (f[98] & UINT32_MAX) * (f[102] & UINT32_MAX);
    f[110] = ((f[110] ^ f[98]) >> 16) | ((f[110] ^ f[98]) << 48);
    f[106] += f[110] + 2 * (f[106] & UINT32_MAX) * (f[110] & UINT32_MAX);
    f[102] = ((f[102] ^ f[106]) >> 63) | ((f[102] ^ f[106]) << 1);
    f[99] += f[103] + 2 * (f[99] & UINT32_MAX) * (f[103] & UINT32_MAX);
    f[111] = ((f[111] ^ f[99]) >> 32) | ((f[111] ^ f[99]) << 32);
    f[107] += f[111] + 2 * (f[107] & UINT32_MAX) * (f[111] & UINT32_MAX);
    f[103] = ((f[103] ^ f[107]) >> 24) | ((f[103] ^ f[107]) << 40);
    f[99] += f[103] + 2 * (f[99] & UINT32_MAX) * (f[103] & UINT32_MAX);
    f[111] = ((f[111] ^ f[99]) >> 16) | ((f[111] ^ f[99]) << 48);
    f[107] += f[111] + 2 * (f[107] & UINT32_MAX) * (f[111] & UINT32_MAX);
    f[103] = ((f[103] ^ f[107]) >> 63) | ((f[103] ^ f[107]) << 1);
    f[96] += f[101] + 2 * (f[96] & UINT32_MAX) * (f[101] & UINT32_MAX);
    f[111] = ((f[111] ^ f[96]) >> 32) | ((f[111] ^ f[96]) << 32);
    f[106] += f[111] + 2 * (f[106] & UINT32_MAX) * (f[111] & UINT32_MAX);
    f[101] = ((f[101] ^ f[106]) >> 24) | ((f[101] ^ f[106]) << 40);
    f[96] += f[101] + 2 * (f[96] & UINT32_MAX) * (f[101] & UINT32_MAX);
    f[111] = ((f[111] ^ f[96]) >> 16) | ((f[111] ^ f[96]) << 48);
    f[106] += f[111] + 2 * (f[106] & UINT32_MAX) * (f[111] & UINT32_MAX);
    f[101] = ((f[101] ^ f[106]) >> 63) | ((f[101] ^ f[106]) << 1);
    f[97] += f[102] + 2 * (f[97] & UINT32_MAX) * (f[102] & UINT32_MAX);
    f[108] = ((f[108] ^ f[97]) >> 32) | ((f[108] ^ f[97]) << 32);
    f[107] += f[108] + 2 * (f[107] & UINT32_MAX) * (f[108] & UINT32_MAX);
    f[102] = ((f[102] ^ f[107]) >> 24) | ((f[102] ^ f[107]) << 40);
    f[97] += f[102] + 2 * (f[97] & UINT32_MAX) * (f[102] & UINT32_MAX);
    f[108] = ((f[108] ^ f[97]) >> 16) | ((f[108] ^ f[97]) << 48);
    f[107] += f[108] + 2 * (f[107] & UINT32_MAX) * (f[108] & UINT32_MAX);
    f[102] = ((f[102] ^ f[107]) >> 63) | ((f[102] ^ f[107]) << 1);
    f[98] += f[103] + 2 * (f[98] & UINT32_MAX) * (f[103] & UINT32_MAX);
    f[109] = ((f[109] ^ f[98]) >> 32) | ((f[109] ^ f[98]) << 32);
    f[104] += f[109] + 2 * (f[104] & UINT32_MAX) * (f[109] & UINT32_MAX);
    f[103] = ((f[103] ^ f[104]) >> 24) | ((f[103] ^ f[104]) << 40);
    f[98] += f[103] + 2 * (f[98] & UINT32_MAX) * (f[103] & UINT32_MAX);
    f[109] = ((f[109] ^ f[98]) >> 16) | ((f[109] ^ f[98]) << 48);
    f[104] += f[109] + 2 * (f[104] & UINT32_MAX) * (f[109] & UINT32_MAX);
    f[103] = ((f[103] ^ f[104]) >> 63) | ((f[103] ^ f[104]) << 1);
    f[99] += f[100] + 2 * (f[99] & UINT32_MAX) * (f[100] & UINT32_MAX);
    f[110] = ((f[110] ^ f[99]) >> 32) | ((f[110] ^ f[99]) << 32);
    f[105] += f[110] + 2 * (f[105] & UINT32_MAX) * (f[110] & UINT32_MAX);
    f[100] = ((f[100] ^ f[105]) >> 24) | ((f[100] ^ f[105]) << 40);
    f[99] += f[100] + 2 * (f[99] & UINT32_MAX) * (f[100] & UINT32_MAX);
    f[110] = ((f[110] ^ f[99]) >> 16) | ((f[110] ^ f[99]) << 48);
    f[105] += f[110] + 2 * (f[105] & UINT32_MAX) * (f[110] & UINT32_MAX);
    f[100] = ((f[100] ^ f[105]) >> 63) | ((f[100] ^ f[105]) << 1);
    f[112] += f[116] + 2 * (f[112] & UINT32_MAX) * (f[116] & UINT32_MAX);
    f[124] = ((f[124] ^ f[112]) >> 32) | ((f[124] ^ f[112]) << 32);
    f[120] += f[124] + 2 * (f[120] & UINT32_MAX) * (f[124] & UINT32_MAX);
    f[116] = ((f[116] ^ f[120]) >> 24) | ((f[116] ^ f[120]) << 40);
    f[112] += f[116] + 2 * (f[112] & UINT32_MAX) * (f[116] & UINT32_MAX);
    f[124] = ((f[124] ^ f[112]) >> 16) | ((f[124] ^ f[112]) << 48);
    f[120] += f[124] + 2 * (f[120] & UINT32_MAX) * (f[124] & UINT32_MAX);
    f[116] = ((f[116] ^ f[120]) >> 63) | ((f[116] ^ f[120]) << 1);
    f[113] += f[117] + 2 * (f[113] & UINT32_MAX) * (f[117] & UINT32_MAX);
    f[125] = ((f[125] ^ f[113]) >> 32) | ((f[125] ^ f[113]) << 32);
    f[121] += f[125] + 2 * (f[121] & UINT32_MAX) * (f[125] & UINT32_MAX);
    f[117] = ((f[117] ^ f[121]) >> 24) | ((f[117] ^ f[121]) << 40);
    f[113] += f[117] + 2 * (f[113] & UINT32_MAX) * (f[117] & UINT32_MAX);
    f[125] = ((f[125] ^ f[113]) >> 16) | ((f[125] ^ f[113]) << 48);
    f[121] += f[125] + 2 * (f[121] & UINT32_MAX) * (f[125] & UINT32_MAX);
    f[117] = ((f[117] ^ f[121]) >> 63) | ((f[117] ^ f[121]) << 1);
    f[114] += f[118] + 2 * (f[114] & UINT32_MAX) * (f[118] & UINT32_MAX);
    f[126] = ((f[126] ^ f[114]) >> 32) | ((f[126] ^ f[114]) << 32);
    f[122] += f[126] + 2 * (f[122] & UINT32_MAX) * (f[126] & UINT32_MAX);
    f[118] = ((f[118] ^ f[122]) >> 24) | ((f[118] ^ f[122]) << 40);
    f[114] += f[118] + 2 * (f[114] & UINT32_MAX) * (f[118] & UINT32_MAX);
    f[126] = ((f[126] ^ f[114]) >> 16) | ((f[126] ^ f[114]) << 48);
    f[122] += f[126] + 2 * (f[122] & UINT32_MAX) * (f[126] & UINT32_MAX);
    f[118] = ((f[118] ^ f[122]) >> 63) | ((f[118] ^ f[122]) << 1);
    f[115] += f[119] + 2 * (f[115] & UINT32_MAX) * (f[119] & UINT32_MAX);
    f[127] = ((f[127] ^ f[115]) >> 32) | ((f[127] ^ f[115]) << 32);
    f[123] += f[127] + 2 * (f[123] & UINT32_MAX) * (f[127] & UINT32_MAX);
    f[119] = ((f[119] ^ f[123]) >> 24) | ((f[119] ^ f[123]) << 40);
    f[115] += f[119] + 2 * (f[115] & UINT32_MAX) * (f[119] & UINT32_MAX);
    f[127] = ((f[127] ^ f[115]) >> 16) | ((f[127] ^ f[115]) << 48);
    f[123] += f[127] + 2 * (f[123] & UINT32_MAX) * (f[127] & UINT32_MAX);
    f[119] = ((f[119] ^ f[123]) >> 63) | ((f[119] ^ f[123]) << 1);
    f[112] += f[117] + 2 * (f[112] & UINT32_MAX) * (f[117] & UINT32_MAX);
    f[127] = ((f[127] ^ f[112]) >> 32) | ((f[127] ^ f[112]) << 32);
    f[122] += f[127] + 2 * (f[122] & UINT32_MAX) * (f[127] & UINT32_MAX);
    f[117] = ((f[117] ^ f[122]) >> 24) | ((f[117] ^ f[122]) << 40);
    f[112] += f[117] + 2 * (f[112] & UINT32_MAX) * (f[117] & UINT32_MAX);
    f[127] = ((f[127] ^ f[112]) >> 16) | ((f[127] ^ f[112]) << 48);
    f[122] += f[127] + 2 * (f[122] & UINT32_MAX) * (f[127] & UINT32_MAX);
    f[117] = ((f[117] ^ f[122]) >> 63) | ((f[117] ^ f[122]) << 1);
    f[113] += f[118] + 2 * (f[113] & UINT32_MAX) * (f[118] & UINT32_MAX);
    f[124] = ((f[124] ^ f[113]) >> 32) | ((f[124] ^ f[113]) << 32);
    f[123] += f[124] + 2 * (f[123] & UINT32_MAX) * (f[124] & UINT32_MAX);
    f[118] = ((f[118] ^ f[123]) >> 24) | ((f[118] ^ f[123]) << 40);
    f[113] += f[118] + 2 * (f[113] & UINT32_MAX) * (f[118] & UINT32_MAX);
    f[124] = ((f[124] ^ f[113]) >> 16) | ((f[124] ^ f[113]) << 48);
    f[123] += f[124] + 2 * (f[123] & UINT32_MAX) * (f[124] & UINT32_MAX);
    f[118] = ((f[118] ^ f[123]) >> 63) | ((f[118] ^ f[123]) << 1);
    f[114] += f[119] + 2 * (f[114] & UINT32_MAX) * (f[119] & UINT32_MAX);
    f[125] = ((f[125] ^ f[114]) >> 32) | ((f[125] ^ f[114]) << 32);
    f[120] += f[125] + 2 * (f[120] & UINT32_MAX) * (f[125] & UINT32_MAX);
    f[119] = ((f[119] ^ f[120]) >> 24) | ((f[119] ^ f[120]) << 40);
    f[114] += f[119] + 2 * (f[114] & UINT32_MAX) * (f[119] & UINT32_MAX);
    f[125] = ((f[125] ^ f[114]) >> 16) | ((f[125] ^ f[114]) << 48);
    f[120] += f[125] + 2 * (f[120] & UINT32_MAX) * (f[125] & UINT32_MAX);
    f[119] = ((f[119] ^ f[120]) >> 63) | ((f[119] ^ f[120]) << 1);
    f[115] += f[116] + 2 * (f[115] & UINT32_MAX) * (f[116] & UINT32_MAX);
    f[126] = ((f[126] ^ f[115]) >> 32) | ((f[126] ^ f[115]) << 32);
    f[121] += f[126] + 2 * (f[121] & UINT32_MAX) * (f[126] & UINT32_MAX);
    f[116] = ((f[116] ^ f[121]) >> 24) | ((f[116] ^ f[121]) << 40);
    f[115] += f[116] + 2 * (f[115] & UINT32_MAX) * (f[116] & UINT32_MAX);
    f[126] = ((f[126] ^ f[115]) >> 16) | ((f[126] ^ f[115]) << 48);
    f[121] += f[126] + 2 * (f[121] & UINT32_MAX) * (f[126] & UINT32_MAX);
    f[116] = ((f[116] ^ f[121]) >> 63) | ((f[116] ^ f[121]) << 1);
    f[0] += f[32] + 2 * (f[0] & UINT32_MAX) * (f[32] & UINT32_MAX);
    f[96] = ((f[96] ^ f[0]) >> 32) | ((f[96] ^ f[0]) << 32);
    f[64] += f[96] + 2 * (f[64] & UINT32_MAX) * (f[96] & UINT32_MAX);
    f[32] = ((f[32] ^ f[64]) >> 24) | ((f[32] ^ f[64]) << 40);
    f[0] += f[32] + 2 * (f[0] & UINT32_MAX) * (f[32] & UINT32_MAX);
    f[96] = ((f[96] ^ f[0]) >> 16) | ((f[96] ^ f[0]) << 48);
    f[64] += f[96] + 2 * (f[64] & UINT32_MAX) * (f[96] & UINT32_MAX);
    f[32] = ((f[32] ^ f[64]) >> 63) | ((f[32] ^ f[64]) << 1);
    f[1] += f[33] + 2 * (f[1] & UINT32_MAX) * (f[33] & UINT32_MAX);
    f[97] = ((f[97] ^ f[1]) >> 32) | ((f[97] ^ f[1]) << 32);
    f[65] += f[97] + 2 * (f[65] & UINT32_MAX) * (f[97] & UINT32_MAX);
    f[33] = ((f[33] ^ f[65]) >> 24) | ((f[33] ^ f[65]) << 40);
    f[1] += f[33] + 2 * (f[1] & UINT32_MAX) * (f[33] & UINT32_MAX);
    f[97] = ((f[97] ^ f[1]) >> 16) | ((f[97] ^ f[1]) << 48);
    f[65] += f[97] + 2 * (f[65] & UINT32_MAX) * (f[97] & UINT32_MAX);
    f[33] = ((f[33] ^ f[65]) >> 63) | ((f[33] ^ f[65]) << 1);
    f[16] += f[48] + 2 * (f[16] & UINT32_MAX) * (f[48] & UINT32_MAX);
    f[112] = ((f[112] ^ f[16]) >> 32) | ((f[112] ^ f[16]) << 32);
    f[80] += f[112] + 2 * (f[80] & UINT32_MAX) * (f[112] & UINT32_MAX);
    f[48] = ((f[48] ^ f[80]) >> 24) | ((f[48] ^ f[80]) << 40);
    f[16] += f[48] + 2 * (f[16] & UINT32_MAX) * (f[48] & UINT32_MAX);
    f[112] = ((f[112] ^ f[16]) >> 16) | ((f[112] ^ f[16]) << 48);
    f[80] += f[112] + 2 * (f[80] & UINT32_MAX) * (f[112] & UINT32_MAX);
    f[48] = ((f[48] ^ f[80]) >> 63) | ((f[48] ^ f[80]) << 1);
    f[17] += f[49] + 2 * (f[17] & UINT32_MAX) * (f[49] & UINT32_MAX);
    f[113] = ((f[113] ^ f[17]) >> 32) | ((f[113] ^ f[17]) << 32);
    f[81] += f[113] + 2 * (f[81] & UINT32_MAX) * (f[113] & UINT32_MAX);
    f[49] = ((f[49] ^ f[81]) >> 24) | ((f[49] ^ f[81]) << 40);
    f[17] += f[49] + 2 * (f[17] & UINT32_MAX) * (f[49] & UINT32_MAX);
    f[113] = ((f[113] ^ f[17]) >> 16) | ((f[113] ^ f[17]) << 48);
    f[81] += f[113] + 2 * (f[81] & UINT32_MAX) * (f[113] & UINT32_MAX);
    f[49] = ((f[49] ^ f[81]) >> 63) | ((f[49] ^ f[81]) << 1);
    f[0] += f[33] + 2 * (f[0] & UINT32_MAX) * (f[33] & UINT32_MAX);
    f[113] = ((f[113] ^ f[0]) >> 32) | ((f[113] ^ f[0]) << 32);
    f[80] += f[113] + 2 * (f[80] & UINT32_MAX) * (f[113] & UINT32_MAX);
    f[33] = ((f[33] ^ f[80]) >> 24) | ((f[33] ^ f[80]) << 40);
    f[0] += f[33] + 2 * (f[0] & UINT32_MAX) * (f[33] & UINT32_MAX);
    f[113] = ((f[113] ^ f[0]) >> 16) | ((f[113] ^ f[0]) << 48);
    f[80] += f[113] + 2 * (f[80] & UINT32_MAX) * (f[113] & UINT32_MAX);
    f[33] = ((f[33] ^ f[80]) >> 63) | ((f[33] ^ f[80]) << 1);
    f[1] += f[48] + 2 * (f[1] & UINT32_MAX) * (f[48] & UINT32_MAX);
    f[96] = ((f[96] ^ f[1]) >> 32) | ((f[96] ^ f[1]) << 32);
    f[81] += f[96] + 2 * (f[81] & UINT32_MAX) * (f[96] & UINT32_MAX);
    f[48] = ((f[48] ^ f[81]) >> 24) | ((f[48] ^ f[81]) << 40);
    f[1] += f[48] + 2 * (f[1] & UINT32_MAX) * (f[48] & UINT32_MAX);
    f[96] = ((f[96] ^ f[1]) >> 16) | ((f[96] ^ f[1]) << 48);
    f[81] += f[96] + 2 * (f[81] & UINT32_MAX) * (f[96] & UINT32_MAX);
    f[48] = ((f[48] ^ f[81]) >> 63) | ((f[48] ^ f[81]) << 1);
    f[16] += f[49] + 2 * (f[16] & UINT32_MAX) * (f[49] & UINT32_MAX);
    f[97] = ((f[97] ^ f[16]) >> 32) | ((f[97] ^ f[16]) << 32);
    f[64] += f[97] + 2 * (f[64] & UINT32_MAX) * (f[97] & UINT32_MAX);
    f[49] = ((f[49] ^ f[64]) >> 24) | ((f[49] ^ f[64]) << 40);
    f[16] += f[49] + 2 * (f[16] & UINT32_MAX) * (f[49] & UINT32_MAX);
    f[97] = ((f[97] ^ f[16]) >> 16) | ((f[97] ^ f[16]) << 48);
    f[64] += f[97] + 2 * (f[64] & UINT32_MAX) * (f[97] & UINT32_MAX);
    f[49] = ((f[49] ^ f[64]) >> 63) | ((f[49] ^ f[64]) << 1);
    f[17] += f[32] + 2 * (f[17] & UINT32_MAX) * (f[32] & UINT32_MAX);
    f[112] = ((f[112] ^ f[17]) >> 32) | ((f[112] ^ f[17]) << 32);
    f[65] += f[112] + 2 * (f[65] & UINT32_MAX) * (f[112] & UINT32_MAX);
    f[32] = ((f[32] ^ f[65]) >> 24) | ((f[32] ^ f[65]) << 40);
    f[17] += f[32] + 2 * (f[17] & UINT32_MAX) * (f[32] & UINT32_MAX);
    f[112] = ((f[112] ^ f[17]) >> 16) | ((f[112] ^ f[17]) << 48);
    f[65] += f[112] + 2 * (f[65] & UINT32_MAX) * (f[112] & UINT32_MAX);
    f[32] = ((f[32] ^ f[65]) >> 63) | ((f[32] ^ f[65]) << 1);
    f[2] += f[34] + 2 * (f[2] & UINT32_MAX) * (f[34] & UINT32_MAX);
    f[98] = ((f[98] ^ f[2]) >> 32) | ((f[98] ^ f[2]) << 32);
    f[66] += f[98] + 2 * (f[66] & UINT32_MAX) * (f[98] & UINT32_MAX);
    f[34] = ((f[34] ^ f[66]) >> 24) | ((f[34] ^ f[66]) << 40);
    f[2] += f[34] + 2 * (f[2] & UINT32_MAX) * (f[34] & UINT32_MAX);
    f[98] = ((f[98] ^ f[2]) >> 16) | ((f[98] ^ f[2]) << 48);
    f[66] += f[98] + 2 * (f[66] & UINT32_MAX) * (f[98] & UINT32_MAX);
    f[34] = ((f[34] ^ f[66]) >> 63) | ((f[34] ^ f[66]) << 1);
    f[3] += f[35] + 2 * (f[3] & UINT32_MAX) * (f[35] & UINT32_MAX);
    f[99] = ((f[99] ^ f[3]) >> 32) | ((f[99] ^ f[3]) << 32);
    f[67] += f[99] + 2 * (f[67] & UINT32_MAX) * (f[99] & UINT32_MAX);
    f[35] = ((f[35] ^ f[67]) >> 24) | ((f[35] ^ f[67]) << 40);
    f[3] += f[35] + 2 * (f[3] & UINT32_MAX) * (f[35] & UINT32_MAX);
    f[99] = ((f[99] ^ f[3]) >> 16) | ((f[99] ^ f[3]) << 48);
    f[67] += f[99] + 2 * (f[67] & UINT32_MAX) * (f[99] & UINT32_MAX);
    f[35] = ((f[35] ^ f[67]) >> 63) | ((f[35] ^ f[67]) << 1);
    f[18] += f[50] + 2 * (f[18] & UINT32_MAX) * (f[50] & UINT32_MAX);
    f[114] = ((f[114] ^ f[18]) >> 32) | ((f[114] ^ f[18]) << 32);
    f[82] += f[114] + 2 * (f[82] & UINT32_MAX) * (f[114] & UINT32_MAX);
    f[50] = ((f[50] ^ f[82]) >> 24) | ((f[50] ^ f[82]) << 40);
    f[18] += f[50] + 2 * (f[18] & UINT32_MAX) * (f[50] & UINT32_MAX);
    f[114] = ((f[114] ^ f[18]) >> 16) | ((f[114] ^ f[18]) << 48);
    f[82] += f[114] + 2 * (f[82] & UINT32_MAX) * (f[114] & UINT32_MAX);
    f[50] = ((f[50] ^ f[82]) >> 63) | ((f[50] ^ f[82]) << 1);
    f[19] += f[51] + 2 * (f[19] & UINT32_MAX) * (f[51] & UINT32_MAX);
    f[115] = ((f[115] ^ f[19]) >> 32) | ((f[115] ^ f[19]) << 32);
    f[83] += f[115] + 2 * (f[83] & UINT32_MAX) * (f[115] & UINT32_MAX);
    f[51] = ((f[51] ^ f[83]) >> 24) | ((f[51] ^ f[83]) << 40);
    f[19] += f[51] + 2 * (f[19] & UINT32_MAX) * (f[51] & UINT32_MAX);
    f[115] = ((f[115] ^ f[19]) >> 16) | ((f[115] ^ f[19]) << 48);
    f[83] += f[115] + 2 * (f[83] & UINT32_MAX) * (f[115] & UINT32_MAX);
    f[51] = ((f[51] ^ f[83]) >> 63) | ((f[51] ^ f[83]) << 1);
    f[2] += f[35] + 2 * (f[2] & UINT32_MAX) * (f[35] & UINT32_MAX);
    f[115] = ((f[115] ^ f[2]) >> 32) | ((f[115] ^ f[2]) << 32);
    f[82] += f[115] + 2 * (f[82] & UINT32_MAX) * (f[115] & UINT32_MAX);
    f[35] = ((f[35] ^ f[82]) >> 24) | ((f[35] ^ f[82]) << 40);
    f[2] += f[35] + 2 * (f[2] & UINT32_MAX) * (f[35] & UINT32_MAX);
    f[115] = ((f[115] ^ f[2]) >> 16) | ((f[115] ^ f[2]) << 48);
    f[82] += f[115] + 2 * (f[82] & UINT32_MAX) * (f[115] & UINT32_MAX);
    f[35] = ((f[35] ^ f[82]) >> 63) | ((f[35] ^ f[82]) << 1);
    f[3] += f[50] + 2 * (f[3] & UINT32_MAX) * (f[50] & UINT32_MAX);
    f[98] = ((f[98] ^ f[3]) >> 32) | ((f[98] ^ f[3]) << 32);
    f[83] += f[98] + 2 * (f[83] & UINT32_MAX) * (f[98] & UINT32_MAX);
    f[50] = ((f[50] ^ f[83]) >> 24) | ((f[50] ^ f[83]) << 40);
    f[3] += f[50] + 2 * (f[3] & UINT32_MAX) * (f[50] & UINT32_MAX);
    f[98] = ((f[98] ^ f[3]) >> 16) | ((f[98] ^ f[3]) << 48);
    f[83] += f[98] + 2 * (f[83] & UINT32_MAX) * (f[98] & UINT32_MAX);
    f[50] = ((f[50] ^ f[83]) >> 63) | ((f[50] ^ f[83]) << 1);
    f[18] += f[51] + 2 * (f[18] & UINT32_MAX) * (f[51] & UINT32_MAX);
    f[99] = ((f[99] ^ f[18]) >> 32) | ((f[99] ^ f[18]) << 32);
    f[66] += f[99] + 2 * (f[66] & UINT32_MAX) * (f[99] & UINT32_MAX);
    f[51] = ((f[51] ^ f[66]) >> 24) | ((f[51] ^ f[66]) << 40);
    f[18] += f[51] + 2 * (f[18] & UINT32_MAX) * (f[51] & UINT32_MAX);
    f[99] = ((f[99] ^ f[18]) >> 16) | ((f[99] ^ f[18]) << 48);
    f[66] += f[99] + 2 * (f[66] & UINT32_MAX) * (f[99] & UINT32_MAX);
    f[51] = ((f[51] ^ f[66]) >> 63) | ((f[51] ^ f[66]) << 1);
    f[19] += f[34] + 2 * (f[19] & UINT32_MAX) * (f[34] & UINT32_MAX);
    f[114] = ((f[114] ^ f[19]) >> 32) | ((f[114] ^ f[19]) << 32);
    f[67] += f[114] + 2 * (f[67] & UINT32_MAX) * (f[114] & UINT32_MAX);
    f[34] = ((f[34] ^ f[67]) >> 24) | ((f[34] ^ f[67]) << 40);
    f[19] += f[34] + 2 * (f[19] & UINT32_MAX) * (f[34] & UINT32_MAX);
    f[114] = ((f[114] ^ f[19]) >> 16) | ((f[114] ^ f[19]) << 48);
    f[67] += f[114] + 2 * (f[67] & UINT32_MAX) * (f[114] & UINT32_MAX);
    f[34] = ((f[34] ^ f[67]) >> 63) | ((f[34] ^ f[67]) << 1);
    f[4] += f[36] + 2 * (f[4] & UINT32_MAX) * (f[36] & UINT32_MAX);
    f[100] = ((f[100] ^ f[4]) >> 32) | ((f[100] ^ f[4]) << 32);
    f[68] += f[100] + 2 * (f[68] & UINT32_MAX) * (f[100] & UINT32_MAX);
    f[36] = ((f[36] ^ f[68]) >> 24) | ((f[36] ^ f[68]) << 40);
    f[4] += f[36] + 2 * (f[4] & UINT32_MAX) * (f[36] & UINT32_MAX);
    f[100] = ((f[100] ^ f[4]) >> 16) | ((f[100] ^ f[4]) << 48);
    f[68] += f[100] + 2 * (f[68] & UINT32_MAX) * (f[100] & UINT32_MAX);
    f[36] = ((f[36] ^ f[68]) >> 63) | ((f[36] ^ f[68]) << 1);
    f[5] += f[37] + 2 * (f[5] & UINT32_MAX) * (f[37] & UINT32_MAX);
    f[101] = ((f[101] ^ f[5]) >> 32) | ((f[101] ^ f[5]) << 32);
    f[69] += f[101] + 2 * (f[69] & UINT32_MAX) * (f[101] & UINT32_MAX);
    f[37] = ((f[37] ^ f[69]) >> 24) | ((f[37] ^ f[69]) << 40);
    f[5] += f[37] + 2 * (f[5] & UINT32_MAX) * (f[37] & UINT32_MAX);
    f[101] = ((f[101] ^ f[5]) >> 16) | ((f[101] ^ f[5]) << 48);
    f[69] += f[101] + 2 * (f[69] & UINT32_MAX) * (f[101] & UINT32_MAX);
    f[37] = ((f[37] ^ f[69]) >> 63) | ((f[37] ^ f[69]) << 1);
    f[20] += f[52] + 2 * (f[20] & UINT32_MAX) * (f[52] & UINT32_MAX);
    f[116] = ((f[116] ^ f[20]) >> 32) | ((f[116] ^ f[20]) << 32);
    f[84] += f[116] + 2 * (f[84] & UINT32_MAX) * (f[116] & UINT32_MAX);
    f[52] = ((f[52] ^ f[84]) >> 24) | ((f[52] ^ f[84]) << 40);
    f[20] += f[52] + 2 * (f[20] & UINT32_MAX) * (f[52] & UINT32_MAX);
    f[116] = ((f[116] ^ f[20]) >> 16) | ((f[116] ^ f[20]) << 48);
    f[84] += f[116] + 2 * (f[84] & UINT32_MAX) * (f[116] & UINT32_MAX);
    f[52] = ((f[52] ^ f[84]) >> 63) | ((f[52] ^ f[84]) << 1);
    f[21] += f[53] + 2 * (f[21] & UINT32_MAX) * (f[53] & UINT32_MAX);
    f[117] = ((f[117] ^ f[21]) >> 32) | ((f[117] ^ f[21]) << 32);
    f[85] += f[117] + 2 * (f[85] & UINT32_MAX) * (f[117] & UINT32_MAX);
    f[53] = ((f[53] ^ f[85]) >> 24) | ((f[53] ^ f[85]) << 40);
    f[21] += f[53] + 2 * (f[21] & UINT32_MAX) * (f[53] & UINT32_MAX);
    f[117] = ((f[117] ^ f[21]) >> 16) | ((f[117] ^ f[21]) << 48);
    f[85] += f[117] + 2 * (f[85] & UINT32_MAX) * (f[117] & UINT32_MAX);
    f[53] = ((f[53] ^ f[85]) >> 63) | ((f[53] ^ f[85]) << 1);
    f[4] += f[37] + 2 * (f[4] & UINT32_MAX) * (f[37] & UINT32_MAX);
    f[117] = ((f[117] ^ f[4]) >> 32) | ((f[117] ^ f[4]) << 32);
    f[84] += f[117] + 2 * (f[84] & UINT32_MAX) * (f[117] & UINT32_MAX);
    f[37] = ((f[37] ^ f[84]) >> 24) | ((f[37] ^ f[84]) << 40);
    f[4] += f[37] + 2 * (f[4] & UINT32_MAX) * (f[37] & UINT32_MAX);
    f[117] = ((f[117] ^ f[4]) >> 16) | ((f[117] ^ f[4]) << 48);
    f[84] += f[117] + 2 * (f[84] & UINT32_MAX) * (f[117] & UINT32_MAX);
    f[37] = ((f[37] ^ f[84]) >> 63) | ((f[37] ^ f[84]) << 1);
    f[5] += f[52] + 2 * (f[5] & UINT32_MAX) * (f[52] & UINT32_MAX);
    f[100] = ((f[100] ^ f[5]) >> 32) | ((f[100] ^ f[5]) << 32);
    f[85] += f[100] + 2 * (f[85] & UINT32_MAX) * (f[100] & UINT32_MAX);
    f[52] = ((f[52] ^ f[85]) >> 24) | ((f[52] ^ f[85]) << 40);
    f[5] += f[52] + 2 * (f[5] & UINT32_MAX) * (f[52] & UINT32_MAX);
    f[100] = ((f[100] ^ f[5]) >> 16) | ((f[100] ^ f[5]) << 48);
    f[85] += f[100] + 2 * (f[85] & UINT32_MAX) * (f[100] & UINT32_MAX);
    f[52] = ((f[52] ^ f[85]) >> 63) | ((f[52] ^ f[85]) << 1);
    f[20] += f[53] + 2 * (f[20] & UINT32_MAX) * (f[53] & UINT32_MAX);
    f[101] = ((f[101] ^ f[20]) >> 32) | ((f[101] ^ f[20]) << 32);
    f[68] += f[101] + 2 * (f[68] & UINT32_MAX) * (f[101] & UINT32_MAX);
    f[53] = ((f[53] ^ f[68]) >> 24) | ((f[53] ^ f[68]) << 40);
    f[20] += f[53] + 2 * (f[20] & UINT32_MAX) * (f[53] & UINT32_MAX);
    f[101] = ((f[101] ^ f[20]) >> 16) | ((f[101] ^ f[20]) << 48);
    f[68] += f[101] + 2 * (f[68] & UINT32_MAX) * (f[101] & UINT32_MAX);
    f[53] = ((f[53] ^ f[68]) >> 63) | ((f[53] ^ f[68]) << 1);
    f[21] += f[36] + 2 * (f[21] & UINT32_MAX) * (f[36] & UINT32_MAX);
    f[116] = ((f[116] ^ f[21]) >> 32) | ((f[116] ^ f[21]) << 32);
    f[69] += f[116] + 2 * (f[69] & UINT32_MAX) * (f[116] & UINT32_MAX);
    f[36] = ((f[36] ^ f[69]) >> 24) | ((f[36] ^ f[69]) << 40);
    f[21] += f[36] + 2 * (f[21] & UINT32_MAX) * (f[36] & UINT32_MAX);
    f[116] = ((f[116] ^ f[21]) >> 16) | ((f[116] ^ f[21]) << 48);
    f[69] += f[116] + 2 * (f[69] & UINT32_MAX) * (f[116] & UINT32_MAX);
    f[36] = ((f[36] ^ f[69]) >> 63) | ((f[36] ^ f[69]) << 1);
    f[6] += f[38] + 2 * (f[6] & UINT32_MAX) * (f[38] & UINT32_MAX);
    f[102] = ((f[102] ^ f[6]) >> 32) | ((f[102] ^ f[6]) << 32);
    f[70] += f[102] + 2 * (f[70] & UINT32_MAX) * (f[102] & UINT32_MAX);
    f[38] = ((f[38] ^ f[70]) >> 24) | ((f[38] ^ f[70]) << 40);
    f[6] += f[38] + 2 * (f[6] & UINT32_MAX) * (f[38] & UINT32_MAX);
    f[102] = ((f[102] ^ f[6]) >> 16) | ((f[102] ^ f[6]) << 48);
    f[70] += f[102] + 2 * (f[70] & UINT32_MAX) * (f[102] & UINT32_MAX);
    f[38] = ((f[38] ^ f[70]) >> 63) | ((f[38] ^ f[70]) << 1);
    f[7] += f[39] + 2 * (f[7] & UINT32_MAX) * (f[39] & UINT32_MAX);
    f[103] = ((f[103] ^ f[7]) >> 32) | ((f[103] ^ f[7]) << 32);
    f[71] += f[103] + 2 * (f[71] & UINT32_MAX) * (f[103] & UINT32_MAX);
    f[39] = ((f[39] ^ f[71]) >> 24) | ((f[39] ^ f[71]) << 40);
    f[7] += f[39] + 2 * (f[7] & UINT32_MAX) * (f[39] & UINT32_MAX);
    f[103] = ((f[103] ^ f[7]) >> 16) | ((f[103] ^ f[7]) << 48);
    f[71] += f[103] + 2 * (f[71] & UINT32_MAX) * (f[103] & UINT32_MAX);
    f[39] = ((f[39] ^ f[71]) >> 63) | ((f[39] ^ f[71]) << 1);
    f[22] += f[54] + 2 * (f[22] & UINT32_MAX) * (f[54] & UINT32_MAX);
    f[118] = ((f[118] ^ f[22]) >> 32) | ((f[118] ^ f[22]) << 32);
    f[86] += f[118] + 2 * (f[86] & UINT32_MAX) * (f[118] & UINT32_MAX);
    f[54] = ((f[54] ^ f[86]) >> 24) | ((f[54] ^ f[86]) << 40);
    f[22] += f[54] + 2 * (f[22] & UINT32_MAX) * (f[54] & UINT32_MAX);
    f[118] = ((f[118] ^ f[22]) >> 16) | ((f[118] ^ f[22]) << 48);
    f[86] += f[118] + 2 * (f[86] & UINT32_MAX) * (f[118] & UINT32_MAX);
    f[54] = ((f[54] ^ f[86]) >> 63) | ((f[54] ^ f[86]) << 1);
    f[23] += f[55] + 2 * (f[23] & UINT32_MAX) * (f[55] & UINT32_MAX);
    f[119] = ((f[119] ^ f[23]) >> 32) | ((f[119] ^ f[23]) << 32);
    f[87] += f[119] + 2 * (f[87] & UINT32_MAX) * (f[119] & UINT32_MAX);
    f[55] = ((f[55] ^ f[87]) >> 24) | ((f[55] ^ f[87]) << 40);
    f[23] += f[55] + 2 * (f[23] & UINT32_MAX) * (f[55] & UINT32_MAX);
    f[119] = ((f[119] ^ f[23]) >> 16) | ((f[119] ^ f[23]) << 48);
    f[87] += f[119] + 2 * (f[87] & UINT32_MAX) * (f[119] & UINT32_MAX);
    f[55] = ((f[55] ^ f[87]) >> 63) | ((f[55] ^ f[87]) << 1);
    f[6] += f[39] + 2 * (f[6] & UINT32_MAX) * (f[39] & UINT32_MAX);
    f[119] = ((f[119] ^ f[6]) >> 32) | ((f[119] ^ f[6]) << 32);
    f[86] += f[119] + 2 * (f[86] & UINT32_MAX) * (f[119] & UINT32_MAX);
    f[39] = ((f[39] ^ f[86]) >> 24) | ((f[39] ^ f[86]) << 40);
    f[6] += f[39] + 2 * (f[6] & UINT32_MAX) * (f[39] & UINT32_MAX);
    f[119] = ((f[119] ^ f[6]) >> 16) | ((f[119] ^ f[6]) << 48);
    f[86] += f[119] + 2 * (f[86] & UINT32_MAX) * (f[119] & UINT32_MAX);
    f[39] = ((f[39] ^ f[86]) >> 63) | ((f[39] ^ f[86]) << 1);
    f[7] += f[54] + 2 * (f[7] & UINT32_MAX) * (f[54] & UINT32_MAX);
    f[102] = ((f[102] ^ f[7]) >> 32) | ((f[102] ^ f[7]) << 32);
    f[87] += f[102] + 2 * (f[87] & UINT32_MAX) * (f[102] & UINT32_MAX);
    f[54] = ((f[54] ^ f[87]) >> 24) | ((f[54] ^ f[87]) << 40);
    f[7] += f[54] + 2 * (f[7] & UINT32_MAX) * (f[54] & UINT32_MAX);
    f[102] = ((f[102] ^ f[7]) >> 16) | ((f[102] ^ f[7]) << 48);
    f[87] += f[102] + 2 * (f[87] & UINT32_MAX) * (f[102] & UINT32_MAX);
    f[54] = ((f[54] ^ f[87]) >> 63) | ((f[54] ^ f[87]) << 1);
    f[22] += f[55] + 2 * (f[22] & UINT32_MAX) * (f[55] & UINT32_MAX);
    f[103] = ((f[103] ^ f[22]) >> 32) | ((f[103] ^ f[22]) << 32);
    f[70] += f[103] + 2 * (f[70] & UINT32_MAX) * (f[103] & UINT32_MAX);
    f[55] = ((f[55] ^ f[70]) >> 24) | ((f[55] ^ f[70]) << 40);
    f[22] += f[55] + 2 * (f[22] & UINT32_MAX) * (f[55] & UINT32_MAX);
    f[103] = ((f[103] ^ f[22]) >> 16) | ((f[103] ^ f[22]) << 48);
    f[70] += f[103] + 2 * (f[70] & UINT32_MAX) * (f[103] & UINT32_MAX);
    f[55] = ((f[55] ^ f[70]) >> 63) | ((f[55] ^ f[70]) << 1);
    f[23] += f[38] + 2 * (f[23] & UINT32_MAX) * (f[38] & UINT32_MAX);
    f[118] = ((f[118] ^ f[23]) >> 32) | ((f[118] ^ f[23]) << 32);
    f[71] += f[118] + 2 * (f[71] & UINT32_MAX) * (f[118] & UINT32_MAX);
    f[38] = ((f[38] ^ f[71]) >> 24) | ((f[38] ^ f[71]) << 40);
    f[23] += f[38] + 2 * (f[23] & UINT32_MAX) * (f[38] & UINT32_MAX);
    f[118] = ((f[118] ^ f[23]) >> 16) | ((f[118] ^ f[23]) << 48);
    f[71] += f[118] + 2 * (f[71] & UINT32_MAX) * (f[118] & UINT32_MAX);
    f[38] = ((f[38] ^ f[71]) >> 63) | ((f[38] ^ f[71]) << 1);
    f[8] += f[40] + 2 * (f[8] & UINT32_MAX) * (f[40] & UINT32_MAX);
    f[104] = ((f[104] ^ f[8]) >> 32) | ((f[104] ^ f[8]) << 32);
    f[72] += f[104] + 2 * (f[72] & UINT32_MAX) * (f[104] & UINT32_MAX);
    f[40] = ((f[40] ^ f[72]) >> 24) | ((f[40] ^ f[72]) << 40);
    f[8] += f[40] + 2 * (f[8] & UINT32_MAX) * (f[40] & UINT32_MAX);
    f[104] = ((f[104] ^ f[8]) >> 16) | ((f[104] ^ f[8]) << 48);
    f[72] += f[104] + 2 * (f[72] & UINT32_MAX) * (f[104] & UINT32_MAX);
    f[40] = ((f[40] ^ f[72]) >> 63) | ((f[40] ^ f[72]) << 1);
    f[9] += f[41] + 2 * (f[9] & UINT32_MAX) * (f[41] & UINT32_MAX);
    f[105] = ((f[105] ^ f[9]) >> 32) | ((f[105] ^ f[9]) << 32);
    f[73] += f[105] + 2 * (f[73] & UINT32_MAX) * (f[105] & UINT32_MAX);
    f[41] = ((f[41] ^ f[73]) >> 24) | ((f[41] ^ f[73]) << 40);
    f[9] += f[41] + 2 * (f[9] & UINT32_MAX) * (f[41] & UINT32_MAX);
    f[105] = ((f[105] ^ f[9]) >> 16) | ((f[105] ^ f[9]) << 48);
    f[73] += f[105] + 2 * (f[73] & UINT32_MAX) * (f[105] & UINT32_MAX);
    f[41] = ((f[41] ^ f[73]) >> 63) | ((f[41] ^ f[73]) << 1);
    f[24] += f[56] + 2 * (f[24] & UINT32_MAX) * (f[56] & UINT32_MAX);
    f[120] = ((f[120] ^ f[24]) >> 32) | ((f[120] ^ f[24]) << 32);
    f[88] += f[120] + 2 * (f[88] & UINT32_MAX) * (f[120] & UINT32_MAX);
    f[56] = ((f[56] ^ f[88]) >> 24) | ((f[56] ^ f[88]) << 40);
    f[24] += f[56] + 2 * (f[24] & UINT32_MAX) * (f[56] & UINT32_MAX);
    f[120] = ((f[120] ^ f[24]) >> 16) | ((f[120] ^ f[24]) << 48);
    f[88] += f[120] + 2 * (f[88] & UINT32_MAX) * (f[120] & UINT32_MAX);
    f[56] = ((f[56] ^ f[88]) >> 63) | ((f[56] ^ f[88]) << 1);
    f[25] += f[57] + 2 * (f[25] & UINT32_MAX) * (f[57] & UINT32_MAX);
    f[121] = ((f[121] ^ f[25]) >> 32) | ((f[121] ^ f[25]) << 32);
    f[89] += f[121] + 2 * (f[89] & UINT32_MAX) * (f[121] & UINT32_MAX);
    f[57] = ((f[57] ^ f[89]) >> 24) | ((f[57] ^ f[89]) << 40);
    f[25] += f[57] + 2 * (f[25] & UINT32_MAX) * (f[57] & UINT32_MAX);
    f[121] = ((f[121] ^ f[25]) >> 16) | ((f[121] ^ f[25]) << 48);
    f[89] += f[121] + 2 * (f[89] & UINT32_MAX) * (f[121] & UINT32_MAX);
    f[57] = ((f[57] ^ f[89]) >> 63) | ((f[57] ^ f[89]) << 1);
    f[8] += f[41] + 2 * (f[8] & UINT32_MAX) * (f[41] & UINT32_MAX);
    f[121] = ((f[121] ^ f[8]) >> 32) | ((f[121] ^ f[8]) << 32);
    f[88] += f[121] + 2 * (f[88] & UINT32_MAX) * (f[121] & UINT32_MAX);
    f[41] = ((f[41] ^ f[88]) >> 24) | ((f[41] ^ f[88]) << 40);
    f[8] += f[41] + 2 * (f[8] & UINT32_MAX) * (f[41] & UINT32_MAX);
    f[121] = ((f[121] ^ f[8]) >> 16) | ((f[121] ^ f[8]) << 48);
    f[88] += f[121] + 2 * (f[88] & UINT32_MAX) * (f[121] & UINT32_MAX);
    f[41] = ((f[41] ^ f[88]) >> 63) | ((f[41] ^ f[88]) << 1);
    f[9] += f[56] + 2 * (f[9] & UINT32_MAX) * (f[56] & UINT32_MAX);
    f[104] = ((f[104] ^ f[9]) >> 32) | ((f[104] ^ f[9]) << 32);
    f[89] += f[104] + 2 * (f[89] & UINT32_MAX) * (f[104] & UINT32_MAX);
    f[56] = ((f[56] ^ f[89]) >> 24) | ((f[56] ^ f[89]) << 40);
    f[9] += f[56] + 2 * (f[9] & UINT32_MAX) * (f[56] & UINT32_MAX);
    f[104] = ((f[104] ^ f[9]) >> 16) | ((f[104] ^ f[9]) << 48);
    f[89] += f[104] + 2 * (f[89] & UINT32_MAX) * (f[104] & UINT32_MAX);
    f[56] = ((f[56] ^ f[89]) >> 63) | ((f[56] ^ f[89]) << 1);
    f[24] += f[57] + 2 * (f[24] & UINT32_MAX) * (f[57] & UINT32_MAX);
    f[105] = ((f[105] ^ f[24]) >> 32) | ((f[105] ^ f[24]) << 32);
    f[72] += f[105] + 2 * (f[72] & UINT32_MAX) * (f[105] & UINT32_MAX);
    f[57] = ((f[57] ^ f[72]) >> 24) | ((f[57] ^ f[72]) << 40);
    f[24] += f[57] + 2 * (f[24] & UINT32_MAX) * (f[57] & UINT32_MAX);
    f[105] = ((f[105] ^ f[24]) >> 16) | ((f[105] ^ f[24]) << 48);
    f[72] += f[105] + 2 * (f[72] & UINT32_MAX) * (f[105] & UINT32_MAX);
    f[57] = ((f[57] ^ f[72]) >> 63) | ((f[57] ^ f[72]) << 1);
    f[25] += f[40] + 2 * (f[25] & UINT32_MAX) * (f[40] & UINT32_MAX);
    f[120] = ((f[120] ^ f[25]) >> 32) | ((f[120] ^ f[25]) << 32);
    f[73] += f[120] + 2 * (f[73] & UINT32_MAX) * (f[120] & UINT32_MAX);
    f[40] = ((f[40] ^ f[73]) >> 24) | ((f[40] ^ f[73]) << 40);
    f[25] += f[40] + 2 * (f[25] & UINT32_MAX) * (f[40] & UINT32_MAX);
    f[120] = ((f[120] ^ f[25]) >> 16) | ((f[120] ^ f[25]) << 48);
    f[73] += f[120] + 2 * (f[73] & UINT32_MAX) * (f[120] & UINT32_MAX);
    f[40] = ((f[40] ^ f[73]) >> 63) | ((f[40] ^ f[73]) << 1);
    f[10] += f[42] + 2 * (f[10] & UINT32_MAX) * (f[42] & UINT32_MAX);
    f[106] = ((f[106] ^ f[10]) >> 32) | ((f[106] ^ f[10]) << 32);
    f[74] += f[106] + 2 * (f[74] & UINT32_MAX) * (f[106] & UINT32_MAX);
    f[42] = ((f[42] ^ f[74]) >> 24) | ((f[42] ^ f[74]) << 40);
    f[10] += f[42] + 2 * (f[10] & UINT32_MAX) * (f[42] & UINT32_MAX);
    f[106] = ((f[106] ^ f[10]) >> 16) | ((f[106] ^ f[10]) << 48);
    f[74] += f[106] + 2 * (f[74] & UINT32_MAX) * (f[106] & UINT32_MAX);
    f[42] = ((f[42] ^ f[74]) >> 63) | ((f[42] ^ f[74]) << 1);
    f[11] += f[43] + 2 * (f[11] & UINT32_MAX) * (f[43] & UINT32_MAX);
    f[107] = ((f[107] ^ f[11]) >> 32) | ((f[107] ^ f[11]) << 32);
    f[75] += f[107] + 2 * (f[75] & UINT32_MAX) * (f[107] & UINT32_MAX);
    f[43] = ((f[43] ^ f[75]) >> 24) | ((f[43] ^ f[75]) << 40);
    f[11] += f[43] + 2 * (f[11] & UINT32_MAX) * (f[43] & UINT32_MAX);
    f[107] = ((f[107] ^ f[11]) >> 16) | ((f[107] ^ f[11]) << 48);
    f[75] += f[107] + 2 * (f[75] & UINT32_MAX) * (f[107] & UINT32_MAX);
    f[43] = ((f[43] ^ f[75]) >> 63) | ((f[43] ^ f[75]) << 1);
    f[26] += f[58] + 2 * (f[26] & UINT32_MAX) * (f[58] & UINT32_MAX);
    f[122] = ((f[122] ^ f[26]) >> 32) | ((f[122] ^ f[26]) << 32);
    f[90] += f[122] + 2 * (f[90] & UINT32_MAX) * (f[122] & UINT32_MAX);
    f[58] = ((f[58] ^ f[90]) >> 24) | ((f[58] ^ f[90]) << 40);
    f[26] += f[58] + 2 * (f[26] & UINT32_MAX) * (f[58] & UINT32_MAX);
    f[122] = ((f[122] ^ f[26]) >> 16) | ((f[122] ^ f[26]) << 48);
    f[90] += f[122] + 2 * (f[90] & UINT32_MAX) * (f[122] & UINT32_MAX);
    f[58] = ((f[58] ^ f[90]) >> 63) | ((f[58] ^ f[90]) << 1);
    f[27] += f[59] + 2 * (f[27] & UINT32_MAX) * (f[59] & UINT32_MAX);
    f[123] = ((f[123] ^ f[27]) >> 32) | ((f[123] ^ f[27]) << 32);
    f[91] += f[123] + 2 * (f[91] & UINT32_MAX) * (f[123] & UINT32_MAX);
    f[59] = ((f[59] ^ f[91]) >> 24) | ((f[59] ^ f[91]) << 40);
    f[27] += f[59] + 2 * (f[27] & UINT32_MAX) * (f[59] & UINT32_MAX);
    f[123] = ((f[123] ^ f[27]) >> 16) | ((f[123] ^ f[27]) << 48);
    f[91] += f[123] + 2 * (f[91] & UINT32_MAX) * (f[123] & UINT32_MAX);
    f[59] = ((f[59] ^ f[91]) >> 63) | ((f[59] ^ f[91]) << 1);
    f[10] += f[43] + 2 * (f[10] & UINT32_MAX) * (f[43] & UINT32_MAX);
    f[123] = ((f[123] ^ f[10]) >> 32) | ((f[123] ^ f[10]) << 32);
    f[90] += f[123] + 2 * (f[90] & UINT32_MAX) * (f[123] & UINT32_MAX);
    f[43] = ((f[43] ^ f[90]) >> 24) | ((f[43] ^ f[90]) << 40);
    f[10] += f[43] + 2 * (f[10] & UINT32_MAX) * (f[43] & UINT32_MAX);
    f[123] = ((f[123] ^ f[10]) >> 16) | ((f[123] ^ f[10]) << 48);
    f[90] += f[123] + 2 * (f[90] & UINT32_MAX) * (f[123] & UINT32_MAX);
    f[43] = ((f[43] ^ f[90]) >> 63) | ((f[43] ^ f[90]) << 1);
    f[11] += f[58] + 2 * (f[11] & UINT32_MAX) * (f[58] & UINT32_MAX);
    f[106] = ((f[106] ^ f[11]) >> 32) | ((f[106] ^ f[11]) << 32);
    f[91] += f[106] + 2 * (f[91] & UINT32_MAX) * (f[106] & UINT32_MAX);
    f[58] = ((f[58] ^ f[91]) >> 24) | ((f[58] ^ f[91]) << 40);
    f[11] += f[58] + 2 * (f[11] & UINT32_MAX) * (f[58] & UINT32_MAX);
    f[106] = ((f[106] ^ f[11]) >> 16) | ((f[106] ^ f[11]) << 48);
    f[91] += f[106] + 2 * (f[91] & UINT32_MAX) * (f[106] & UINT32_MAX);
    f[58] = ((f[58] ^ f[91]) >> 63) | ((f[58] ^ f[91]) << 1);
    f[26] += f[59] + 2 * (f[26] & UINT32_MAX) * (f[59] & UINT32_MAX);
    f[107] = ((f[107] ^ f[26]) >> 32) | ((f[107] ^ f[26]) << 32);
    f[74] += f[107] + 2 * (f[74] & UINT32_MAX) * (f[107] & UINT32_MAX);
    f[59] = ((f[59] ^ f[74]) >> 24) | ((f[59] ^ f[74]) << 40);
    f[26] += f[59] + 2 * (f[26] & UINT32_MAX) * (f[59] & UINT32_MAX);
    f[107] = ((f[107] ^ f[26]) >> 16) | ((f[107] ^ f[26]) << 48);
    f[74] += f[107] + 2 * (f[74] & UINT32_MAX) * (f[107] & UINT32_MAX);
    f[59] = ((f[59] ^ f[74]) >> 63) | ((f[59] ^ f[74]) << 1);
    f[27] += f[42] + 2 * (f[27] & UINT32_MAX) * (f[42] & UINT32_MAX);
    f[122] = ((f[122] ^ f[27]) >> 32) | ((f[122] ^ f[27]) << 32);
    f[75] += f[122] + 2 * (f[75] & UINT32_MAX) * (f[122] & UINT32_MAX);
    f[42] = ((f[42] ^ f[75]) >> 24) | ((f[42] ^ f[75]) << 40);
    f[27] += f[42] + 2 * (f[27] & UINT32_MAX) * (f[42] & UINT32_MAX);
    f[122] = ((f[122] ^ f[27]) >> 16) | ((f[122] ^ f[27]) << 48);
    f[75] += f[122] + 2 * (f[75] & UINT32_MAX) * (f[122] & UINT32_MAX);
    f[42] = ((f[42] ^ f[75]) >> 63) | ((f[42] ^ f[75]) << 1);
    f[12] += f[44] + 2 * (f[12] & UINT32_MAX) * (f[44] & UINT32_MAX);
    f[108] = ((f[108] ^ f[12]) >> 32) | ((f[108] ^ f[12]) << 32);
    f[76] += f[108] + 2 * (f[76] & UINT32_MAX) * (f[108] & UINT32_MAX);
    f[44] = ((f[44] ^ f[76]) >> 24) | ((f[44] ^ f[76]) << 40);
    f[12] += f[44] + 2 * (f[12] & UINT32_MAX) * (f[44] & UINT32_MAX);
    f[108] = ((f[108] ^ f[12]) >> 16) | ((f[108] ^ f[12]) << 48);
    f[76] += f[108] + 2 * (f[76] & UINT32_MAX) * (f[108] & UINT32_MAX);
    f[44] = ((f[44] ^ f[76]) >> 63) | ((f[44] ^ f[76]) << 1);
    f[13] += f[45] + 2 * (f[13] & UINT32_MAX) * (f[45] & UINT32_MAX);
    f[109] = ((f[109] ^ f[13]) >> 32) | ((f[109] ^ f[13]) << 32);
    f[77] += f[109] + 2 * (f[77] & UINT32_MAX) * (f[109] & UINT32_MAX);
    f[45] = ((f[45] ^ f[77]) >> 24) | ((f[45] ^ f[77]) << 40);
    f[13] += f[45] + 2 * (f[13] & UINT32_MAX) * (f[45] & UINT32_MAX);
    f[109] = ((f[109] ^ f[13]) >> 16) | ((f[109] ^ f[13]) << 48);
    f[77] += f[109] + 2 * (f[77] & UINT32_MAX) * (f[109] & UINT32_MAX);
    f[45] = ((f[45] ^ f[77]) >> 63) | ((f[45] ^ f[77]) << 1);
    f[28] += f[60] + 2 * (f[28] & UINT32_MAX) * (f[60] & UINT32_MAX);
    f[124] = ((f[124] ^ f[28]) >> 32) | ((f[124] ^ f[28]) << 32);
    f[92] += f[124] + 2 * (f[92] & UINT32_MAX) * (f[124] & UINT32_MAX);
    f[60] = ((f[60] ^ f[92]) >> 24) | ((f[60] ^ f[92]) << 40);
    f[28] += f[60] + 2 * (f[28] & UINT32_MAX) * (f[60] & UINT32_MAX);
    f[124] = ((f[124] ^ f[28]) >> 16) | ((f[124] ^ f[28]) << 48);
    f[92] += f[124] + 2 * (f[92] & UINT32_MAX) * (f[124] & UINT32_MAX);
    f[60] = ((f[60] ^ f[92]) >> 63) | ((f[60] ^ f[92]) << 1);
    f[29] += f[61] + 2 * (f[29] & UINT32_MAX) * (f[61] & UINT32_MAX);
    f[125] = ((f[125] ^ f[29]) >> 32) | ((f[125] ^ f[29]) << 32);
    f[93] += f[125] + 2 * (f[93] & UINT32_MAX) * (f[125] & UINT32_MAX);
    f[61] = ((f[61] ^ f[93]) >> 24) | ((f[61] ^ f[93]) << 40);
    f[29] += f[61] + 2 * (f[29] & UINT32_MAX) * (f[61] & UINT32_MAX);
    f[125] = ((f[125] ^ f[29]) >> 16) | ((f[125] ^ f[29]) << 48);
    f[93] += f[125] + 2 * (f[93] & UINT32_MAX) * (f[125] & UINT32_MAX);
    f[61] = ((f[61] ^ f[93]) >> 63) | ((f[61] ^ f[93]) << 1);
    f[12] += f[45] + 2 * (f[12] & UINT32_MAX) * (f[45] & UINT32_MAX);
    f[125] = ((f[125] ^ f[12]) >> 32) | ((f[125] ^ f[12]) << 32);
    f[92] += f[125] + 2 * (f[92] & UINT32_MAX) * (f[125] & UINT32_MAX);
    f[45] = ((f[45] ^ f[92]) >> 24) | ((f[45] ^ f[92]) << 40);
    f[12] += f[45] + 2 * (f[12] & UINT32_MAX) * (f[45] & UINT32_MAX);
    f[125] = ((f[125] ^ f[12]) >> 16) | ((f[125] ^ f[12]) << 48);
    f[92] += f[125] + 2 * (f[92] & UINT32_MAX) * (f[125] & UINT32_MAX);
    f[45] = ((f[45] ^ f[92]) >> 63) | ((f[45] ^ f[92]) << 1);
    f[13] += f[60] + 2 * (f[13] & UINT32_MAX) * (f[60] & UINT32_MAX);
    f[108] = ((f[108] ^ f[13]) >> 32) | ((f[108] ^ f[13]) << 32);
    f[93] += f[108] + 2 * (f[93] & UINT32_MAX) * (f[108] & UINT32_MAX);
    f[60] = ((f[60] ^ f[93]) >> 24) | ((f[60] ^ f[93]) << 40);
    f[13] += f[60] + 2 * (f[13] & UINT32_MAX) * (f[60] & UINT32_MAX);
    f[108] = ((f[108] ^ f[13]) >> 16) | ((f[108] ^ f[13]) << 48);
    f[93] += f[108] + 2 * (f[93] & UINT32_MAX) * (f[108] & UINT32_MAX);
    f[60] = ((f[60] ^ f[93]) >> 63) | ((f[60] ^ f[93]) << 1);
    f[28] += f[61] + 2 * (f[28] & UINT32_MAX) * (f[61] & UINT32_MAX);
    f[109] = ((f[109] ^ f[28]) >> 32) | ((f[109] ^ f[28]) << 32);
    f[76] += f[109] + 2 * (f[76] & UINT32_MAX) * (f[109] & UINT32_MAX);
    f[61] = ((f[61] ^ f[76]) >> 24) | ((f[61] ^ f[76]) << 40);
    f[28] += f[61] + 2 * (f[28] & UINT32_MAX) * (f[61] & UINT32_MAX);
    f[109] = ((f[109] ^ f[28]) >> 16) | ((f[109] ^ f[28]) << 48);
    f[76] += f[109] + 2 * (f[76] & UINT32_MAX) * (f[109] & UINT32_MAX);
    f[61] = ((f[61] ^ f[76]) >> 63) | ((f[61] ^ f[76]) << 1);
    f[29] += f[44] + 2 * (f[29] & UINT32_MAX) * (f[44] & UINT32_MAX);
    f[124] = ((f[124] ^ f[29]) >> 32) | ((f[124] ^ f[29]) << 32);
    f[77] += f[124] + 2 * (f[77] & UINT32_MAX) * (f[124] & UINT32_MAX);
    f[44] = ((f[44] ^ f[77]) >> 24) | ((f[44] ^ f[77]) << 40);
    f[29] += f[44] + 2 * (f[29] & UINT32_MAX) * (f[44] & UINT32_MAX);
    f[124] = ((f[124] ^ f[29]) >> 16) | ((f[124] ^ f[29]) << 48);
    f[77] += f[124] + 2 * (f[77] & UINT32_MAX) * (f[124] & UINT32_MAX);
    f[44] = ((f[44] ^ f[77]) >> 63) | ((f[44] ^ f[77]) << 1);
    f[14] += f[46] + 2 * (f[14] & UINT32_MAX) * (f[46] & UINT32_MAX);
    f[110] = ((f[110] ^ f[14]) >> 32) | ((f[110] ^ f[14]) << 32);
    f[78] += f[110] + 2 * (f[78] & UINT32_MAX) * (f[110] & UINT32_MAX);
    f[46] = ((f[46] ^ f[78]) >> 24) | ((f[46] ^ f[78]) << 40);
    f[14] += f[46] + 2 * (f[14] & UINT32_MAX) * (f[46] & UINT32_MAX);
    f[110] = ((f[110] ^ f[14]) >> 16) | ((f[110] ^ f[14]) << 48);
    f[78] += f[110] + 2 * (f[78] & UINT32_MAX) * (f[110] & UINT32_MAX);
    f[46] = ((f[46] ^ f[78]) >> 63) | ((f[46] ^ f[78]) << 1);
    f[15] += f[47] + 2 * (f[15] & UINT32_MAX) * (f[47] & UINT32_MAX);
    f[111] = ((f[111] ^ f[15]) >> 32) | ((f[111] ^ f[15]) << 32);
    f[79] += f[111] + 2 * (f[79] & UINT32_MAX) * (f[111] & UINT32_MAX);
    f[47] = ((f[47] ^ f[79]) >> 24) | ((f[47] ^ f[79]) << 40);
    f[15] += f[47] + 2 * (f[15] & UINT32_MAX) * (f[47] & UINT32_MAX);
    f[111] = ((f[111] ^ f[15]) >> 16) | ((f[111] ^ f[15]) << 48);
    f[79] += f[111] + 2 * (f[79] & UINT32_MAX) * (f[111] & UINT32_MAX);
    f[47] = ((f[47] ^ f[79]) >> 63) | ((f[47] ^ f[79]) << 1);
    f[30] += f[62] + 2 * (f[30] & UINT32_MAX) * (f[62] & UINT32_MAX);
    f[126] = ((f[126] ^ f[30]) >> 32) | ((f[126] ^ f[30]) << 32);
    f[94] += f[126] + 2 * (f[94] & UINT32_MAX) * (f[126] & UINT32_MAX);
    f[62] = ((f[62] ^ f[94]) >> 24) | ((f[62] ^ f[94]) << 40);
    f[30] += f[62] + 2 * (f[30] & UINT32_MAX) * (f[62] & UINT32_MAX);
    f[126] = ((f[126] ^ f[30]) >> 16) | ((f[126] ^ f[30]) << 48);
    f[94] += f[126] + 2 * (f[94] & UINT32_MAX) * (f[126] & UINT32_MAX);
    f[62] = ((f[62] ^ f[94]) >> 63) | ((f[62] ^ f[94]) << 1);
    f[31] += f[63] + 2 * (f[31] & UINT32_MAX) * (f[63] & UINT32_MAX);
    f[127] = ((f[127] ^ f[31]) >> 32) | ((f[127] ^ f[31]) << 32);
    f[95] += f[127] + 2 * (f[95] & UINT32_MAX) * (f[127] & UINT32_MAX);
    f[63] = ((f[63] ^ f[95]) >> 24) | ((f[63] ^ f[95]) << 40);
    f[31] += f[63] + 2 * (f[31] & UINT32_MAX) * (f[63] & UINT32_MAX);
    f[127] = ((f[127] ^ f[31]) >> 16) | ((f[127] ^ f[31]) << 48);
    f[95] += f[127] + 2 * (f[95] & UINT32_MAX) * (f[127] & UINT32_MAX);
    f[63] = ((f[63] ^ f[95]) >> 63) | ((f[63] ^ f[95]) << 1);
    f[14] += f[47] + 2 * (f[14] & UINT32_MAX) * (f[47] & UINT32_MAX);
    f[127] = ((f[127] ^ f[14]) >> 32) | ((f[127] ^ f[14]) << 32);
    f[94] += f[127] + 2 * (f[94] & UINT32_MAX) * (f[127] & UINT32_MAX);
    f[47] = ((f[47] ^ f[94]) >> 24) | ((f[47] ^ f[94]) << 40);
    f[14] += f[47] + 2 * (f[14] & UINT32_MAX) * (f[47] & UINT32_MAX);
    f[127] = ((f[127] ^ f[14]) >> 16) | ((f[127] ^ f[14]) << 48);
    f[94] += f[127] + 2 * (f[94] & UINT32_MAX) * (f[127] & UINT32_MAX);
    f[47] = ((f[47] ^ f[94]) >> 63) | ((f[47] ^ f[94]) << 1);
    f[15] += f[62] + 2 * (f[15] & UINT32_MAX) * (f[62] & UINT32_MAX);
    f[110] = ((f[110] ^ f[15]) >> 32) | ((f[110] ^ f[15]) << 32);
    f[95] += f[110] + 2 * (f[95] & UINT32_MAX) * (f[110] & UINT32_MAX);
    f[62] = ((f[62] ^ f[95]) >> 24) | ((f[62] ^ f[95]) << 40);
    f[15] += f[62] + 2 * (f[15] & UINT32_MAX) * (f[62] & UINT32_MAX);
    f[110] = ((f[110] ^ f[15]) >> 16) | ((f[110] ^ f[15]) << 48);
    f[95] += f[110] + 2 * (f[95] & UINT32_MAX) * (f[110] & UINT32_MAX);
    f[62] = ((f[62] ^ f[95]) >> 63) | ((f[62] ^ f[95]) << 1);
    f[30] += f[63] + 2 * (f[30] & UINT32_MAX) * (f[63] & UINT32_MAX);
    f[111] = ((f[111] ^ f[30]) >> 32) | ((f[111] ^ f[30]) << 32);
    f[78] += f[111] + 2 * (f[78] & UINT32_MAX) * (f[111] & UINT32_MAX);
    f[63] = ((f[63] ^ f[78]) >> 24) | ((f[63] ^ f[78]) << 40);
    f[30] += f[63] + 2 * (f[30] & UINT32_MAX) * (f[63] & UINT32_MAX);
    f[111] = ((f[111] ^ f[30]) >> 16) | ((f[111] ^ f[30]) << 48);
    f[78] += f[111] + 2 * (f[78] & UINT32_MAX) * (f[111] & UINT32_MAX);
    f[63] = ((f[63] ^ f[78]) >> 63) | ((f[63] ^ f[78]) << 1);
    f[31] += f[46] + 2 * (f[31] & UINT32_MAX) * (f[46] & UINT32_MAX);
    f[126] = ((f[126] ^ f[31]) >> 32) | ((f[126] ^ f[31]) << 32);
    f[79] += f[126] + 2 * (f[79] & UINT32_MAX) * (f[126] & UINT32_MAX);
    f[46] = ((f[46] ^ f[79]) >> 24) | ((f[46] ^ f[79]) << 40);
    f[31] += f[46] + 2 * (f[31] & UINT32_MAX) * (f[46] & UINT32_MAX);
    f[126] = ((f[126] ^ f[31]) >> 16) | ((f[126] ^ f[31]) << 48);
    f[79] += f[126] + 2 * (f[79] & UINT32_MAX) * (f[126] & UINT32_MAX);
    f[46] = ((f[46] ^ f[79]) >> 63) | ((f[46] ^ f[79]) << 1);

    for (i = 0; i < BLOCK_BYTES / 16; i++) {
        put_little_end_64(z + i * 16, f[2 * i]);
        put_little_end_64(z + i * 16 + 8, f[2 * i + 1]);
    }

    if (xor_output) {
        for (i = 0; i < BLOCK_BYTES; i++) {
            output_block[i] ^= z[i] ^ r[i];
        }
    }
    else {
        for (i = 0; i < BLOCK_BYTES; i++) {
            output_block[i] = z[i] ^ r[i];
        }
    }
}
