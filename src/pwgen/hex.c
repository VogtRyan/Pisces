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

#include "hex.h"

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "common/scrub.h"
#include "crypto/abstract/cprng.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static void get_hex_chars(char *pwd, size_t pwdlen, char ten_char);

void generate_pwd_hex_lowercase(char *pwd, size_t pwdlen)
{
    get_hex_chars(pwd, pwdlen, 'a');
}

void generate_pwd_hex_uppercase(char *pwd, size_t pwdlen)
{
    get_hex_chars(pwd, pwdlen, 'A');
}

size_t bits_security_hex(size_t pwdlen)
{
    ASSERT(pwdlen <= SIZE_MAX / 4, "Multiplication overflow");
    return pwdlen * 4;
}

static void get_hex_chars(char *pwd, size_t pwdlen, char ten_char)
{
    struct cprng *rng;
    size_t gen_size, i;
    byte *rand_buf;
    byte current;
    bool move_raw;

    gen_size = pwdlen / 2;
    if (pwdlen & 0x1) {
        gen_size++;
    }
    rand_buf = (byte *)malloc(gen_size);
    GUARD_ALLOC(rand_buf);

    /* Two unbiased hex characters for every random byte */
    rng = cprng_alloc_default();
    cprng_bytes(rng, rand_buf, gen_size);
    i = 0;
    move_raw = false;
    while (pwdlen > 0) {
        current = (byte)(rand_buf[i] & 0x0F);
        if (current <= (byte)9) {
            *pwd = '0' + (char)current;
        }
        else {
            *pwd = ten_char + (char)current - (char)10;
        }
        pwd++;
        pwdlen--;
        if (move_raw) {
            i++;
            move_raw = false;
        }
        else {
            rand_buf[i] >>= 4;
            move_raw = true;
        }
    }

    cprng_free_scrub(rng);
    scrub_memory(rand_buf, gen_size);
    free(rand_buf);
}
