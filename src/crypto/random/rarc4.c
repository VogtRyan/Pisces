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

#include "rarc4.h"

#include "common/errorflow.h"

#include <stddef.h>
#include <stdlib.h>

#define UNUSED(x) (void)(x)

#ifdef PISCES_NO_ARC4RANDOM

void rarc4_fill(byte *output, size_t output_len)
{
    UNUSED(output);
    UNUSED(output_len);
    ASSERT_NEVER_REACH("Pisces compiled without arc4random_buf() support");
}

#else

/*
 * Expose arc4random_buf(), even when a _POSIX_C_SOURCE feature test macro
 * hides it.
 */
extern void arc4random_buf(void *buf, size_t nbytes);

void rarc4_fill(byte *output, size_t output_len)
{
    arc4random_buf(output, output_len);
}

#endif

/*
 * Some static analysis tools produce a warning if arc4random_buf() does not
 * have an implementation (corresponding to the extern function declaration) in
 * the Pisces codebase. Suppress that warning with a dead-code implementation
 * that does not even get compiled.
 */
#if 0
static void arc4random_buf(void *buf, size_t nbytes) {}
#endif
