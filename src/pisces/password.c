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

#include "password.h"

#include "common/bytetype.h"
#include "common/config.h"
#include "common/errorflow.h"
#include "common/scrub.h"

#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>

#define ENCRYPT_MESSAGE "Enter a password to encrypt this file: "
#define CONFIRM_MESSAGE "Reenter the password to encrypt this file: "
#define DECRYPT_MESSAGE "Enter the password to decrypt this file: "

#define PASSWORD_TOO_LONG_MESSAGE "Password can be at most %d characters long"

static int use_provided_password(char *password, size_t *password_len,
                                 const char *provided_password);
static int password_strlen(const char *provided, size_t *password_len);

static int read_secret_input_line(char *line, size_t *line_len,
                                  const char *prompt);
static int read_input_line(FILE *fp, char *line, size_t *line_len);

int get_encryption_password(char *password, size_t *password_len,
                            const char *provided_password)
{
    char input1[PASSWORD_LENGTH_MAX];
    char input2[PASSWORD_LENGTH_MAX];
    size_t len1, len2;
    int errval = 0;

    if (provided_password != NULL) {
        if (use_provided_password(password, password_len, provided_password)) {
            ERROR_QUIET(done, errval);
        }
    }
    else {
        if (read_secret_input_line(input1, &len1, ENCRYPT_MESSAGE)) {
            ERROR_QUIET(done, errval);
        }
        if (read_secret_input_line(input2, &len2, CONFIRM_MESSAGE)) {
            ERROR_QUIET(done, errval);
        }
        if (len1 != len2 || memcmp(input1, input2, len1) != 0) {
            ERROR(done, errval, "Passwords do not match");
        }

        /* Only write to caller's memory if password is valid */
        memcpy(password, input1, len1);
        *password_len = len1;
    }

done:
    scrub_memory(input1, PASSWORD_LENGTH_MAX);
    scrub_memory(input2, PASSWORD_LENGTH_MAX);
    scrub_memory(&len1, sizeof(size_t));
    scrub_memory(&len2, sizeof(size_t));
    return errval;
}

int get_decryption_password(char *password, size_t *password_len,
                            const char *provided_password)
{
    char input[PASSWORD_LENGTH_MAX];
    size_t len;
    int errval = 0;

    if (provided_password != NULL) {
        if (use_provided_password(password, password_len, provided_password)) {
            ERROR_QUIET(done, errval);
        }
    }
    else {
        if (read_secret_input_line(input, &len, DECRYPT_MESSAGE)) {
            ERROR_QUIET(done, errval);
        }

        /* Only write to caller's memory if password is valid */
        memcpy(password, input, len);
        *password_len = len;
    }

done:
    scrub_memory(input, PASSWORD_LENGTH_MAX);
    scrub_memory(&len, sizeof(size_t));
    return errval;
}

static int use_provided_password(char *password, size_t *password_len,
                                 const char *provided_password)
{
    int errval = 0;

    if (password_strlen(provided_password, password_len)) {
        ERROR_QUIET(done, errval);
    }

    /* Only write to caller's memory if password is valid */
    memcpy(password, provided_password, *password_len);

done:
    return errval;
}

static int password_strlen(const char *provided, size_t *password_len)
{
    size_t len = 0;
    int errval = 0;

    /* Portable replacement for strnlen, for POSIX-1.2001 compatibility */
    while (len < PASSWORD_LENGTH_MAX) {
        if (provided[len] == '\0') {
            break;
        }
        len++;
    }
    if (provided[len] != '\0') {
        ERROR(done, errval, PASSWORD_TOO_LONG_MESSAGE, PASSWORD_LENGTH_MAX);
    }

    /* Only write to caller's memory if password is valid */
    *password_len = len;

done:
    scrub_memory(&len, sizeof(size_t));
    return errval;
}

static int read_secret_input_line(char *line, size_t *line_len,
                                  const char *prompt)
{
    /*
     * The following function is adapted from the char* getpass(const char*)
     * function from p.350 of "Advanced Programming in the UNIX Environment"
     * by W. Richard Stevens (ISBN 0201563177)
     */

    sigset_t sig, sigsave;
    struct termios term, termsave;
    FILE *fp;
    int errval = 0;

    fp = fopen(ctermid(NULL), "r+");
    if (fp == NULL) {
        FATAL_ERROR("Could not open terminal for reading");
    }
    fprintf(fp, "%s", prompt);
    setbuf(fp, NULL);

    sigemptyset(&sig);
    sigaddset(&sig, SIGINT);
    sigaddset(&sig, SIGTSTP);
    sigprocmask(SIG_BLOCK, &sig, &sigsave);

    tcgetattr(fileno(fp), &termsave);
    term = termsave;
    term.c_lflag &= (tcflag_t)(~(ECHO | ECHOE | ECHOK | ECHONL));
    tcsetattr(fileno(fp), TCSAFLUSH, &term);

    if (read_input_line(fp, line, line_len)) {
        ERROR(done, errval, PASSWORD_TOO_LONG_MESSAGE, PASSWORD_LENGTH_MAX);
    }

done:
    tcsetattr(fileno(fp), TCSAFLUSH, &termsave);
    sigprocmask(SIG_SETMASK, &sigsave, NULL);
    fclose(fp);
    return errval;
}

static int read_input_line(FILE *fp, char *line, size_t *line_len)
{
    int c;
    int ret = 0;

    *line_len = 0;
    while ((c = getc(fp)) != EOF && c != '\n') {
        if (*line_len < PASSWORD_LENGTH_MAX) {
            line[(*line_len)++] = (char)c;
        }
        else {
            ret = -1;
        }
    }
    putc('\n', fp);

    scrub_memory(&c, sizeof(int));
    return ret;
}
