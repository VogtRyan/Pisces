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

#include "common/config.h"
#include "common/errorflow.h"
#include "common/scrub.h"

#include <sys/stat.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void parse_command_line(int argc, char **argv, bool *encrypt,
                               char **input_file, char **output_file,
                               char **password);
static bool is_stdin_stdout(const char *cmdline_arg);

static int sanity_check_files(char *input_file, char *output_file);

static int fill_password(char *password, size_t *password_len,
                         const char *cmdline_password, bool encrypt);
static int run_cipher_op(const char *input_file, const char *output_file,
                         const char *password, size_t password_len,
                         bool encrypt);

static void usage(void);

int main(int argc, char **argv)
{
    char password[PASSWORD_LENGTH_MAX];
    char *cmdline_password;
    char *input_file, *output_file;
    size_t password_len;
    bool encrypt;
    int errval;

    parse_command_line(argc, argv, &encrypt, &input_file, &output_file,
                       &cmdline_password);
    if (sanity_check_files(input_file, output_file)) {
        return EXIT_FAILURE;
    }
    if (fill_password(password, &password_len, cmdline_password, encrypt)) {
        return EXIT_FAILURE;
    }

    errval = run_cipher_op(input_file, output_file, password, password_len,
                           encrypt);
    scrub_memory(password, PASSWORD_LENGTH_MAX);
    scrub_memory(&password_len, sizeof(size_t));
    return (errval ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void parse_command_line(int argc, char **argv, bool *encrypt,
                               char **input_file, char **output_file,
                               char **password)
{
    bool op_specified;
    int ch;

    *encrypt = true;
    *password = NULL;
    op_specified = false;

    while ((ch = getopt(argc, argv, "edp:v")) != -1) {
        switch (ch) {
        case 'e':
            if (op_specified && (*encrypt == false)) {
                usage();
            }
            op_specified = true;
            *encrypt = true;
            break;
        case 'd':
            if (op_specified && *encrypt) {
                usage();
            }
            op_specified = true;
            *encrypt = false;
            break;
        case 'p':
            if (*password != NULL) {
                /*
                 * Do not accept any sort of pathological command-line
                 * behaviour related to the password, even if the same password
                 * is given twice.
                 */
                usage();
            }
            *password = optarg;
            break;
        case 'v':
            printf("pisces version %s\n", IMPLEMENTATION_VERSION);
            exit(EXIT_SUCCESS);
        default:
            usage();
        }
    }

    if (argc - optind != 2) {
        usage();
    }
    *input_file = argv[argc - 2];
    *output_file = argv[argc - 1];

    if (is_stdin_stdout(*input_file)) {
        *input_file = NULL;
    }
    if (is_stdin_stdout(*output_file)) {
        *output_file = NULL;
    }
}

static bool is_stdin_stdout(const char *cmdline_arg)
{
    return (cmdline_arg[0] == '-' && cmdline_arg[1] == '\0');
}

static int sanity_check_files(char *input_file, char *output_file)
{
    struct stat in_stat, out_stat;

    /* Check that we can operate on the type of input file */
    if (input_file != NULL) {
        if (stat(input_file, &in_stat)) {
            ERROR_RETURN("Could not stat input file: %s", input_file);
        }
        if (S_ISDIR(in_stat.st_mode)) {
            ERROR_RETURN("Cannot operate on directories");
        }
    }

    /* Ensure, as well as possible, that the two files are different */
    if (input_file != NULL && output_file != NULL) {
        if (stat(output_file, &out_stat) == 0) {
            if (in_stat.st_dev == out_stat.st_dev &&
                in_stat.st_ino == out_stat.st_ino) {
                ERROR_RETURN("Input file and output file are the same");
            }
        }
    }

    return 0;
}

static int fill_password(char *password, size_t *password_len,
                         const char *cmdline_password, bool encrypt)
{
    /*
     * The password buffer and length will not be written to unless the
     * function call below succeeds. There is no need to scrub memory on
     * failure.
     */
    if (cmdline_password != NULL) {
        return password_copy(password, password_len, cmdline_password);
    }
    else if (encrypt) {
        return password_prompt_encryption(password, password_len);
    }
    else {
        return password_prompt_decryption(password, password_len);
    }
}

static int run_cipher_op(const char *input_file, const char *output_file,
                         const char *password, size_t password_len,
                         bool encrypt)
{
    if (encrypt) {
        pisces_set_version(PISCES_VERSION_NEWEST);
        return encrypt_file(input_file, output_file, password, password_len);
    }
    else {
        return decrypt_file(input_file, output_file, password, password_len);
    }
}

static void usage(void)
{
    fprintf(ERROR_OUTPUT,
            "usage: pisces [-dev] [-p password] input_file output_file\n");
    exit(EXIT_FAILURE);
}
