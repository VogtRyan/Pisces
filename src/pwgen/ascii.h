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

#ifndef PISCES_PWGEN_ASCII_H_
#define PISCES_PWGEN_ASCII_H_

#include <stddef.h>

/*
 * Fills the result array with the requested number of unbiased characters from
 * the prinable ASCII set, excluding whitespace.
 */
void get_ascii(char *result, size_t num);

/*
 * Returns the number of bits of security offered by a get_ascii password of
 * the given length.
 */
double bits_security_ascii(size_t num);

/*
 * Fills the result array with the requested number of unbiased characters from
 * the set of uppercase, lowercase, and numeric characters in the standard
 * ASCII character set.
 */
void get_alpha_num(char *result, size_t num);

/*
 * Returns the number of bits of security offered by a get_alpha_num password
 * of the given length.
 */
double bits_security_alpha_num(size_t num);

/*
 * Fills the result array with the requested number of numeric characters.
 */
void get_numeric(char *result, size_t num);

/*
 * Returns the number of bits of security offered by a get_numeric password of
 * the given length.
 */
double bits_security_numeric(size_t num);

#endif
