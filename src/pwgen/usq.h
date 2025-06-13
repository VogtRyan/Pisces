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

#ifndef PISCES_PWGEN_USQ_H_
#define PISCES_PWGEN_USQ_H_

#include <stddef.h>

/*
 * The USQ Simple character set includes all the uppercase, lowercase, and
 * numeric characters in the standard ASCII set. Additionally, it includes the
 * ten symbols typeable by pressing "Shift" and a number key on a US QWERTY
 * keyboard:
 *
 *     ! @ # $ % ^ & * ( )
 *
 * A USQ Enforced password comes from the USQ Simple character set, but is
 * guaranteed to contain at least one lowercase letter, one uppercase letter,
 * one number, and one symbol.
 */

void generate_pwd_usq_simple(char *pwd, size_t pwdlen);
double bits_security_usq_simple(size_t pwdlen);

void generate_pwd_usq_simple_enforced(char *pwd, size_t pwdlen);
double bits_security_usq_simple_enforced(size_t pwdlen);

#endif
