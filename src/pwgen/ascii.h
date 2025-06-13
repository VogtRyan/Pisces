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
 * The ASCII character set is the printable ASCII characters (33 to 126; the
 * space at 32 is excluded).
 *
 * The alphanumeric character set is all the uppercase, lowercase, and numeric
 * characters in the standard ASCII set.
 *
 * The numeric character set is the digits 0-9.
 */

void generate_pwd_ascii(char *pwd, size_t pwdlen);
double bits_security_ascii(size_t pwdlen);

void generate_pwd_alpha_num(char *pwd, size_t pwdlen);
double bits_security_alpha_num(size_t pwdlen);

void generate_pwd_numeric(char *pwd, size_t pwdlen);
double bits_security_numeric(size_t pwdlen);

#endif
