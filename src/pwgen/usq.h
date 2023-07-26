/*
 * Copyright (c) 2008-2023 Ryan Vogt <rvogt.ca@gmail.com>
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

#ifndef PISCES_PWGEN_USQ_H_
#define PISCES_PWGEN_USQ_H_

#include <stddef.h>

/*
 * Fills the result array with the requested number of unbiased characters, all
 * of which can be typed simply on a U.S. QWERTY keyboard. That set of
 * characters comprises uppercase and lowercase letters, numbers, and symbol
 * characters that can be typed by holding down the shift key while pressing a
 * number key.
 */
void get_usq_simple(char *result, size_t num);

/*
 * Fills the result array with the same types of characters used by
 * get_usq_simple(). But, results are guaranteed to contain at least one
 * uppercase character, at least one lowercase character, at least one number,
 * and at least one special character. These guarantees are made in a way as to
 * produce unbiased generated passwords.
 */
void get_usq_simple_enforced(char *result, size_t num);

#endif
