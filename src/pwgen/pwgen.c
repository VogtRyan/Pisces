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

/* Default setting is an enforced password of length 20 */
#define DEFAULT_METHOD (get_usq_simple_enforced)
#define DEFAULT_LENGTH (20)

/*
 * Parse the options on the command line, setting the output length and the
 * generation function. On any error, print a message to stderr and exit with
 * a negative code.
 */
static void parse_command_line(int argc, char **argv, size_t *outputLen,
                               void (**genFn)(char *, size_t));

/*
 * Sets the genFn variable to the given value function. If the genFn was not
 * NULL and was set to something different, print the usage message and exit
 * with a negative code.
 */
static void set_generation_fn(void (**genFn)(char *, size_t),
                              void (*value)(char *, size_t));

/*
 * Sets the length variable to the value of the given string argument. If the
 * value is invalid, or not equal to a length that has already been set, print
 * an error and exit with a negative code.
 */
static void set_length_value(size_t *length, char *theArg);

/*
 * Prints the usage message and version number to stderr and exit with a
 * negative code.
 */
static void usage(void);

int main(int argc, char **argv)
{
    size_t length;
    void (*genFn)(char *, size_t);
    char *password = NULL;
    int errVal = 0;

    /* Parse the command line and ensure option sanity */
    parse_command_line(argc, argv, &length, &genFn);
    if (genFn == get_usq_simple_enforced && length < 4) {
        ERROR(isErr, errVal,
              "An \"enforced\" password must have at least four characters");
    }

    /* Allocate memory to hold the generated password */
    ASSERT(length + 1 > length, "Overflow should never happen");
    password = (char *)calloc(length + 1, sizeof(char));
    GUARD_ALLOC(password);

    /* Generate the password and output it */
    genFn(password, length);
    printf("%s\n", password);

isErr:
    if (password != NULL) {
        scrub_memory(password, length);
        free(password);
    }
    return errVal;
}

static void parse_command_line(int argc, char **argv, size_t *outputLen,
                               void (**genFn)(char *, size_t))
{
    int ch;
    *genFn = NULL;
    *outputLen = 0;

    /* Process input options */
    while ((ch = getopt(argc, argv, "aeHhnsl:v")) != -1) {
        switch (ch) {
        case 'a':
            set_generation_fn(genFn, get_ascii);
            break;
        case 'e':
            set_generation_fn(genFn, get_usq_simple_enforced);
            break;
        case 'H':
            set_generation_fn(genFn, get_hex_uppercase);
            break;
        case 'h':
            set_generation_fn(genFn, get_hex_lowercase);
            break;
        case 'n':
            set_generation_fn(genFn, get_alpha_num);
            break;
        case 's':
            set_generation_fn(genFn, get_usq_simple);
            break;
        case 'l':
            set_length_value(outputLen, optarg);
            break;
        default:
            usage();
        }
    }

    if (*genFn == NULL) {
        *genFn = DEFAULT_METHOD;
    }
    if (*outputLen == 0) {
        *outputLen = DEFAULT_LENGTH;
    }
}

static void set_generation_fn(void (**genFn)(char *, size_t),
                              void (*value)(char *, size_t))
{
    if (*genFn == NULL) {
        *genFn = value;
    }
    else if (*genFn != value) {
        usage();
    }
}
static void set_length_value(size_t *length, char *theArg)
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
    else if (*length != 0 && *length != (size_t)lval) {
        usage();
    }

    *length = (size_t)lval;
isErr:
    if (errVal) {
        exit(-1);
    }
}

static void usage(void)
{
    fprintf(stderr, "usage: pwgen [-aeHhns] [-l length]\n");
    fprintf(stderr, "pwgen version %s\n", IMPLEMENTATION_VERSION);
    exit(-1);
}
