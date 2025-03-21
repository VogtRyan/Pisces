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

#include "encryption.h"
#include "password.h"
#include "version.h"

#include "common/errorflow.h"
#include "common/pwlimits.h"
#include "common/scrub.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#define IMPLEMENTATION_VERSION "5.2.2"

/*
 * Parse the command line options passed to Pisces.
 *
 * encrypt will hold 1 if the operation is encryption or 0 for decryption.
 *
 * inputFile and outputFile will point to the relevant arguments within argv,
 * or will be NULL for stdin/stdout.
 *
 * password will point to the relevant argument within argv, or will be NULL
 * if none is provided on the command line.
 *
 * If there is any error processing the arguments, print the usage message to
 * standard error and exit with a negative code.
 */
static void parse_command_line(int argc, char **argv, int *encrypt,
                               char **inputFile, char **outputFile,
                               char **password);

/*
 * Stat the input file to check its type, and ensure that the input file
 * and output file are distinct. Return 0 on success, -1 on error (and
 * print error messages).
 */
static int check_files(char *inputFile, char *outputFile);

/*
 * Prints the usage message and version number to stderr and exit with a
 * negative code.
 */
static void usage(void);

int main(int argc, char **argv)
{
    char password[PASSWORD_LENGTH_MAX];
    size_t passwordLen;
    char *providedPassword;
    char *inputFile, *outputFile;
    int encrypt;
    int errVal = 0;

    /* Parse the command line, stat the input file, and ensure file safety */
    parse_command_line(argc, argv, &encrypt, &inputFile, &outputFile,
                       &providedPassword);
    if (check_files(inputFile, outputFile)) {
        ERROR_QUIET(isErr, errVal);
    }

    /* Get the user's password */
    if (encrypt) {
        if (get_encryption_password(password, &passwordLen,
                                    providedPassword)) {
            ERROR_QUIET(isErr, errVal);
        }
    }
    else {
        if (get_decryption_password(password, &passwordLen,
                                    providedPassword)) {
            ERROR_QUIET(isErr, errVal);
        }
    }

    /* Perform the encryption or decryption */
    if (encrypt) {
        pisces_set_version(PISCES_VERSION_NEWEST);
        if (encrypt_file(inputFile, outputFile, password, passwordLen)) {
            ERROR_QUIET(isErr, errVal);
        }
    }
    else {
        if (decrypt_file(inputFile, outputFile, password, passwordLen)) {
            ERROR_QUIET(isErr, errVal);
        }
    }

isErr:
    scrub_memory(password, PASSWORD_LENGTH_MAX);
    scrub_memory(&passwordLen, sizeof(size_t));
    return errVal ? -1 : 0;
}

static void parse_command_line(int argc, char **argv, int *encrypt,
                               char **inputFile, char **outputFile,
                               char **password)
{
    int opSpecified;
    int ch;
    int needInput, needOutput;

    /* Default operation is encryption, interactive password, files */
    *encrypt = 1;
    *password = NULL;
    needInput = needOutput = 1;

    /* Process input options */
    opSpecified = 0;
    while ((ch = getopt(argc, argv, "edp:iov")) != -1) {
        switch (ch) {
        case 'e':
            if (opSpecified && (*encrypt == 0)) {
                usage();
            }
            opSpecified = 1;
            *encrypt = 1;
            break;
        case 'd':
            if (opSpecified && (*encrypt == 1)) {
                usage();
            }
            opSpecified = 1;
            *encrypt = 0;
            break;
        case 'p':
            if (*password != NULL) {
                /*
                 * Don't bother to see if two passwords specified on the
                 * command line are the same; just quit with a usage error.
                 */
                usage();
            }
            *password = optarg;
            break;
        case 'i':
            needInput = 0;
            break;
        case 'o':
            needOutput = 0;
            break;
        default:
            usage();
        }
    }

    /* Ensure correctness of option flags */
    if (argc - optind != needInput + needOutput) {
        usage();
    }

    /* Process the input and output files */
    if (needInput) {
        *inputFile = argv[argc - (needInput + needOutput)];
    }
    else {
        *inputFile = NULL;
    }

    if (needOutput) {
        *outputFile = argv[argc - 1];
    }
    else {
        *outputFile = NULL;
    }
}

static int check_files(char *inputFile, char *outputFile)
{
    struct stat inStat, outStat;
    int errVal = 0;

    /* Stat the input file to check its type */
    if (inputFile != NULL) {
        if (stat(inputFile, &inStat)) {
            ERROR(isErr, errVal, "Could not stat input file: %s", inputFile);
        }
        if (S_ISDIR(inStat.st_mode)) {
            ERROR(isErr, errVal, "Cannot operate on directories");
        }
    }

    /* Ensure, as well as possible, that the two files are different */
    if (inputFile != NULL && outputFile != NULL) {
        if (stat(outputFile, &outStat) == 0) {
            if (inStat.st_dev == outStat.st_dev &&
                inStat.st_ino == outStat.st_ino) {
                ERROR(isErr, errVal,
                      "Input file and output file are the same");
            }
        }
    }

isErr:
    return errVal ? -1 : 0;
}

static void usage(void)
{
    fprintf(stderr,
            "usage: pisces [-de] [-p password] input_file output_file\n"
            "       pisces [-de] [-p password] -i output_file\n"
            "       pisces [-de] [-p password] -o input_file\n"
            "       pisces [-de] [-p password] -i -o\n");
    fprintf(stderr, "pisces version %s\n", IMPLEMENTATION_VERSION);
    exit(-1);
}
