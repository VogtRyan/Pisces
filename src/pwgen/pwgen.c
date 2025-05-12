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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Supported password-generation functions */
typedef enum {
    GEN_FN_ALPHA_NUM,
    GEN_FN_ASCII,
    GEN_FN_HEX_LOWER,
    GEN_FN_HEX_UPPER,
    GEN_FN_USQ_ENFORCED,
    GEN_FN_USQ_SIMPLE
} gen_fn_t;

/* Password generation settings if none specified on the command line */
#define DEFAULT_GEN_FN (GEN_FN_USQ_ENFORCED)
#define DEFAULT_LENGTH (24)

/*
 * Fill the password array with the given number of random characters, using
 * the provided function.
 */
static void generate_password(char *password, size_t length, gen_fn_t genFn);

/*
 * Parse the options on the command line, setting the output length and the
 * generation function. On any error, print a message to stderr and exit with
 * a negative code.
 */
static void parse_command_line(int argc, char **argv, gen_fn_t *genFn,
                               size_t *outputLen);

/*
 * If no generation function has yet been set, set the function to newGenFn and
 * raise the genFnSet flag. If the generation function has already been set to
 * a different value, print the usage message and exit with a negative code.
 */
static void set_generation_fn(gen_fn_t *genFn, int *genFnSet,
                              gen_fn_t newGenFn);

/*
 * Sets the length variable to the value of the given string argument. If the
 * value is invalid, or not equal to a length that has already been set, print
 * an error and exit with a negative code.
 */
static void set_length_value(size_t *length, char *theArg);

/*
 * Parse the length variable from a string format. If the value is invalid
 * (including if it's larger than the maximum password length), print an error
 * and return -1. Otherwise, return 0.
 */
static int parse_length_value(size_t *result, char *theArg);

/*
 * Prints the usage message and version number to stderr and exit with a
 * negative code.
 */
static void usage(void);

int main(int argc, char **argv)
{
    gen_fn_t genFn;
    size_t length;
    char *password = NULL;
    int errVal = 0;

    /* Parse the command line and ensure option sanity */
    parse_command_line(argc, argv, &genFn, &length);
    if (genFn == GEN_FN_USQ_ENFORCED && length < 4) {
        ERROR(isErr, errVal,
              "An \"enforced\" password must have at least four characters");
    }

    /* Allocate memory to hold the generated password */
    ASSERT(length + 1 > length, "Overflow should never happen");
    password = (char *)calloc(length + 1, sizeof(char));
    GUARD_ALLOC(password);

    /* Generate the password and output it */
    generate_password(password, length, genFn);
    printf("%s\n", password);

isErr:
    if (password != NULL) {
        scrub_memory(password, length);
        free(password);
    }
    return errVal;
}

static void generate_password(char *password, size_t length, gen_fn_t genFn)
{
    switch (genFn) {
    case GEN_FN_ALPHA_NUM:
        get_alpha_num(password, length);
        break;
    case GEN_FN_ASCII:
        get_ascii(password, length);
        break;
    case GEN_FN_HEX_LOWER:
        get_hex_lowercase(password, length);
        break;
    case GEN_FN_HEX_UPPER:
        get_hex_uppercase(password, length);
        break;
    case GEN_FN_USQ_ENFORCED:
        get_usq_simple_enforced(password, length);
        break;
    case GEN_FN_USQ_SIMPLE:
        get_usq_simple(password, length);
        break;
    default:
        ASSERT_NEVER_REACH("Invalid password-generation function");
    }
}

static void parse_command_line(int argc, char **argv, gen_fn_t *genFn,
                               size_t *outputLen)
{
    int genFnSet = 0;
    int ch;

    *genFn = DEFAULT_GEN_FN;
    *outputLen = 0;

    while ((ch = getopt(argc, argv, "aeHhnsl:v")) != -1) {
        switch (ch) {
        case 'a':
            set_generation_fn(genFn, &genFnSet, GEN_FN_ASCII);
            break;
        case 'e':
            set_generation_fn(genFn, &genFnSet, GEN_FN_USQ_ENFORCED);
            break;
        case 'H':
            set_generation_fn(genFn, &genFnSet, GEN_FN_HEX_UPPER);
            break;
        case 'h':
            set_generation_fn(genFn, &genFnSet, GEN_FN_HEX_LOWER);
            break;
        case 'n':
            set_generation_fn(genFn, &genFnSet, GEN_FN_ALPHA_NUM);
            break;
        case 's':
            set_generation_fn(genFn, &genFnSet, GEN_FN_USQ_SIMPLE);
            break;
        case 'l':
            set_length_value(outputLen, optarg);
            break;
        default:
            usage();
        }
    }

    if (*outputLen == 0) {
        *outputLen = DEFAULT_LENGTH;
    }
}

static void set_generation_fn(gen_fn_t *genFn, int *genFnSet,
                              gen_fn_t newGenFn)
{
    if (*genFnSet == 0) {
        *genFn = newGenFn;
        *genFnSet = 1;
    }
    else if (*genFn != newGenFn) {
        usage();
    }
}

static void set_length_value(size_t *length, char *theArg)
{
    size_t newLen;

    if (parse_length_value(&newLen, theArg)) {
        exit(-1);
    }

    if (*length != 0 && *length != newLen) {
        usage();
    }

    *length = newLen;
}

static int parse_length_value(size_t *result, char *theArg)
{
    long lval;
    char *ep;
    int errVal = 0;

    errno = 0;
    lval = strtol(theArg, &ep, 10);
    if (theArg[0] == '\0' || *ep != '\0') {
        ERROR(isErr, errVal, "Invalid length: \'%s\'", theArg);
    }
    else if (errno == ERANGE && (lval == LONG_MAX || lval == LONG_MIN)) {
        ERROR(isErr, errVal, "Length out of range: \'%s\'", theArg);
    }
    else if (lval > PASSWORD_LENGTH_MAX) {
        ERROR(isErr, errVal, "Length must be no greater than %d: \'%s\'",
              PASSWORD_LENGTH_MAX, theArg);
    }
    else if (lval <= 0) {
        ERROR(isErr, errVal, "Length must be greater than zero: \'%s\'",
              theArg);
    }

    *result = (size_t)lval;
isErr:
    return errVal;
}

static void usage(void)
{
    fprintf(stderr, "usage: pwgen [-aeHhns] [-l length]\n");
    fprintf(stderr, "pwgen version %s\n", IMPLEMENTATION_VERSION);
    exit(-1);
}
