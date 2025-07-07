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

#include "ascii.h"
#include "hex.h"
#include "usq.h"

#include "common/config.h"
#include "common/errorflow.h"
#include "common/scrub.h"

#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef enum {
    GEN_FN_ALPHA_NUM,
    GEN_FN_ASCII,
    GEN_FN_HEX_LOWER,
    GEN_FN_HEX_UPPER,
    GEN_FN_NUMERIC,
    GEN_FN_USQ_ENFORCED,
    GEN_FN_USQ_SIMPLE
} gen_fn;

#define DEFAULT_GEN_FN (GEN_FN_USQ_ENFORCED)
#define DEFAULT_LENGTH (24)

static void generate_password(size_t pwdlen, gen_fn gfn);
static void run_gen_fn(char *password, size_t pwdlen, gen_fn gfn);

static void describe_gen_fn(size_t pwdlen, gen_fn gfn);
static void print_description_decimal(const char *gfn_name, size_t pwdlen,
                                      double bits_sec);
static void print_description_whole(const char *gfn_name, size_t pwdlen,
                                    size_t bits_sec);
static void print_description_prefix(const char *gfn_name, size_t pwdlen);

static void parse_command_line(int argc, char **argv, gen_fn *gfn,
                               size_t *pwdlen, bool *describe);

static void set_generation_fn(gen_fn *gfn, bool *gfn_set, gen_fn new_gfn);
static void set_length_value(size_t *pwdlen, char *cmdline_arg);
static int parse_length_value(size_t *pwdlen, char *cmdline_arg);
static int sanity_check_length(gen_fn gfn, size_t pwdlen);

static void usage(void);

int main(int argc, char **argv)
{
    gen_fn gfn;
    size_t pwdlen;
    bool describe;

    parse_command_line(argc, argv, &gfn, &pwdlen, &describe);
    if (sanity_check_length(gfn, pwdlen)) {
        return EXIT_FAILURE;
    }

    if (describe) {
        describe_gen_fn(pwdlen, gfn);
    }
    else {
        generate_password(pwdlen, gfn);
    }
    scrub_memory(&pwdlen, sizeof(size_t));
    return EXIT_SUCCESS;
}

static void generate_password(size_t pwdlen, gen_fn gfn)
{
    char *password;

    ASSERT(pwdlen + 1 > pwdlen, "Allocation computation overflow");
    password = (char *)calloc(pwdlen + 1, sizeof(char));
    GUARD_ALLOC(password);

    run_gen_fn(password, pwdlen, gfn);

    printf("%s\n", password);
    scrub_memory(password, pwdlen);
    scrub_memory(&pwdlen, sizeof(size_t));
    free(password);
}

static void run_gen_fn(char *password, size_t pwdlen, gen_fn gfn)
{
    switch (gfn) {
    case GEN_FN_ALPHA_NUM:
        generate_pwd_alpha_num(password, pwdlen);
        break;
    case GEN_FN_ASCII:
        generate_pwd_ascii(password, pwdlen);
        break;
    case GEN_FN_HEX_LOWER:
        generate_pwd_hex_lowercase(password, pwdlen);
        break;
    case GEN_FN_HEX_UPPER:
        generate_pwd_hex_uppercase(password, pwdlen);
        break;
    case GEN_FN_NUMERIC:
        generate_pwd_numeric(password, pwdlen);
        break;
    case GEN_FN_USQ_ENFORCED:
        generate_pwd_usq_simple_enforced(password, pwdlen);
        break;
    case GEN_FN_USQ_SIMPLE:
        generate_pwd_usq_simple(password, pwdlen);
        break;
    default:
        ASSERT_NEVER_REACH("Invalid password-generation function");
    }
}

static void describe_gen_fn(size_t pwdlen, gen_fn gfn)
{
    switch (gfn) {
    case GEN_FN_ALPHA_NUM:
        print_description_decimal("Alphanumeric", pwdlen,
                                  bits_security_alpha_num(pwdlen));
        break;
    case GEN_FN_ASCII:
        print_description_decimal("ASCII", pwdlen,
                                  bits_security_ascii(pwdlen));
        break;
    case GEN_FN_HEX_LOWER:
        print_description_whole("Hexadecimal (lowercase)", pwdlen,
                                bits_security_hex(pwdlen));
        break;
    case GEN_FN_HEX_UPPER:
        print_description_whole("Hexadecimal (uppercase)", pwdlen,
                                bits_security_hex(pwdlen));
        break;
    case GEN_FN_NUMERIC:
        print_description_decimal("Numeric PIN", pwdlen,
                                  bits_security_numeric(pwdlen));
        break;
    case GEN_FN_USQ_ENFORCED:
        print_description_decimal(
            "Enforced (uppercase, lowercase, number, and U.S. QWERTY simple "
            "symbol)",
            pwdlen, bits_security_usq_simple_enforced(pwdlen));
        break;
    case GEN_FN_USQ_SIMPLE:
        print_description_decimal("U.S. QWERTY with simple symbols", pwdlen,
                                  bits_security_usq_simple(pwdlen));
        break;
    default:
        ASSERT_NEVER_REACH("Invalid password-generation function");
    }
}

static void print_description_decimal(const char *name, size_t pwdlen,
                                      double bits_sec)
{
    double trunc;

    print_description_prefix(name, pwdlen);
    trunc = floor(bits_sec * 1000) / 1000;
    printf("%.3lf\n", trunc);
}

static void print_description_whole(const char *name, size_t pwdlen,
                                    size_t bits_sec)
{
    print_description_prefix(name, pwdlen);
    printf("%zu\n", bits_sec);
}

static void print_description_prefix(const char *name, size_t pwdlen)
{
    printf("Method: %s\n", name);
    printf("Length: %zu\n", pwdlen);
    printf("Bits of security: ");
}

static void parse_command_line(int argc, char **argv, gen_fn *gfn,
                               size_t *pwdlen, bool *describe)
{
    bool gfn_set;
    int ch;

    *gfn = DEFAULT_GEN_FN;
    gfn_set = false;
    *pwdlen = 0;
    *describe = false;

    while ((ch = getopt(argc, argv, "adeHhnpsl:v")) != -1) {
        switch (ch) {
        case 'a':
            set_generation_fn(gfn, &gfn_set, GEN_FN_ASCII);
            break;
        case 'e':
            set_generation_fn(gfn, &gfn_set, GEN_FN_USQ_ENFORCED);
            break;
        case 'H':
            set_generation_fn(gfn, &gfn_set, GEN_FN_HEX_UPPER);
            break;
        case 'h':
            set_generation_fn(gfn, &gfn_set, GEN_FN_HEX_LOWER);
            break;
        case 'n':
            set_generation_fn(gfn, &gfn_set, GEN_FN_ALPHA_NUM);
            break;
        case 'p':
            set_generation_fn(gfn, &gfn_set, GEN_FN_NUMERIC);
            break;
        case 's':
            set_generation_fn(gfn, &gfn_set, GEN_FN_USQ_SIMPLE);
            break;
        case 'l':
            set_length_value(pwdlen, optarg);
            break;
        case 'd':
            *describe = true;
            break;
        case 'v':
            printf("pwgen version %s\n", IMPLEMENTATION_VERSION);
            exit(EXIT_SUCCESS);
        default:
            usage();
        }
    }

    if (argc - optind != 0) {
        usage();
    }

    if (*pwdlen == 0) {
        *pwdlen = DEFAULT_LENGTH;
    }
}

static void set_generation_fn(gen_fn *gfn, bool *gfn_set, gen_fn new_gfn)
{
    if (*gfn_set == false) {
        *gfn = new_gfn;
        *gfn_set = true;
    }
    else if (*gfn != new_gfn) {
        usage();
    }
}

static void set_length_value(size_t *pwdlen, char *cmdline_arg)
{
    size_t newlen;

    if (parse_length_value(&newlen, cmdline_arg)) {
        exit(EXIT_FAILURE);
    }

    if (*pwdlen != 0 && *pwdlen != newlen) {
        usage();
    }

    *pwdlen = newlen;
}

static int parse_length_value(size_t *pwdlen, char *cmdline_arg)
{
    long lval;
    char *ep;

    errno = 0;
    lval = strtol(cmdline_arg, &ep, 10);
    if (cmdline_arg[0] == '\0' || *ep != '\0') {
        ERROR_RETURN("Invalid length: \'%s\'", cmdline_arg);
    }
    else if (errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) {
        ERROR_RETURN("Length out of range: \'%s\'", cmdline_arg);
    }
    else if (lval > PASSWORD_LENGTH_MAX) {
        ERROR_RETURN("Length must be no greater than %d: \'%s\'",
                     PASSWORD_LENGTH_MAX, cmdline_arg);
    }
    else if (lval <= 0) {
        ERROR_RETURN("Length must be greater than zero: \'%s\'", cmdline_arg);
    }

    *pwdlen = (size_t)lval;
    return 0;
}

static int sanity_check_length(gen_fn gfn, size_t pwdlen)
{
    if (gfn == GEN_FN_USQ_ENFORCED && pwdlen < 4) {
        ERROR_RETURN(
            "An \"enforced\" password must have at least four characters");
    }
    return 0;
}

static void usage(void)
{
    fprintf(ERROR_OUTPUT, "usage: pwgen [-adeHhnpsv] [-l length]\n");
    exit(EXIT_FAILURE);
}
