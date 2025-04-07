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

/*
 * Messages to display to the user prompting for a password.
 */
#define ENCRYPT_MESSAGE "Enter a password to encrypt this file: "
#define CONFIRM_MESSAGE "Reenter the password to encrypt this file: "
#define DECRYPT_MESSAGE "Enter the password to decrypt this file: "

/*
 * Copies the provided password into the password array and sets the value of
 * passwordLen. Returns 0 on success, -1 on error (and prints error messages).
 */
static int use_provided_password(char *password, size_t *passwordLen,
                                 const char *providedPassword);

/*
 * Finds the length of the given NULL-terminated password and returns 0; or,
 * returns -1 if the provided password is too long (and prints error messages).
 * Essentially a portable substitute for strnlen(), for POSIX.1-2001
 * compatibility.
 */
static int password_strlen(const char *provided, size_t *passwordLen);

/*
 * The array userInput must be at least PASSWORD_LENGTH_MAX in size.
 * Returns 0 on success, -1 on error (and prints error messages).
 */
static int get_secret_input(const char *prompt, char *userInput,
                            size_t *passwordLen);

int get_encryption_password(char *password, size_t *passwordLen,
                            const char *providedPassword)
{
    char input1[PASSWORD_LENGTH_MAX];
    char input2[PASSWORD_LENGTH_MAX];
    size_t len1, len2;
    int errVal = 0;

    if (providedPassword != NULL) {
        if (use_provided_password(password, passwordLen, providedPassword)) {
            ERROR_QUIET(isErr, errVal);
        }
    }
    else {
        if (get_secret_input(ENCRYPT_MESSAGE, input1, &len1)) {
            ERROR_QUIET(isErr, errVal);
        }
        if (get_secret_input(CONFIRM_MESSAGE, input2, &len2)) {
            ERROR_QUIET(isErr, errVal);
        }
        if (len1 != len2 || memcmp(input1, input2, len1) != 0) {
            ERROR(isErr, errVal, "Passwords do not match");
        }
        memcpy(password, input1, len1);
        *passwordLen = len1;
    }

isErr:
    scrub_memory(input1, PASSWORD_LENGTH_MAX);
    scrub_memory(input2, PASSWORD_LENGTH_MAX);
    scrub_memory(&len1, sizeof(size_t));
    scrub_memory(&len2, sizeof(size_t));
    return errVal;
}

int get_decryption_password(char *password, size_t *passwordLen,
                            const char *providedPassword)
{
    char input[PASSWORD_LENGTH_MAX];
    size_t len;
    int errVal = 0;

    if (providedPassword != NULL) {
        if (use_provided_password(password, passwordLen, providedPassword)) {
            ERROR_QUIET(isErr, errVal);
        }
    }
    else {
        if (get_secret_input(DECRYPT_MESSAGE, input, &len)) {
            ERROR_QUIET(isErr, errVal);
        }
        memcpy(password, input, len);
        *passwordLen = len;
    }

isErr:
    scrub_memory(input, PASSWORD_LENGTH_MAX);
    scrub_memory(&len, sizeof(size_t));
    return errVal;
}

static int use_provided_password(char *password, size_t *passwordLen,
                                 const char *providedPassword)
{
    int errVal = 0;

    if (password_strlen(providedPassword, passwordLen)) {
        ERROR_QUIET(isErr, errVal);
    }
    memcpy(password, providedPassword, *passwordLen);

isErr:
    return errVal;
}

static int password_strlen(const char *provided, size_t *passwordLen)
{
    size_t len = 0;
    int errVal = 0;

    while (len < PASSWORD_LENGTH_MAX) {
        if (provided[len] == '\0') {
            break;
        }
        len++;
    }
    if (provided[len] != '\0') {
        ERROR(isErr, errVal, "Password can be at most %d characters long",
              PASSWORD_LENGTH_MAX);
    }
    *passwordLen = len;

isErr:
    scrub_memory(&len, sizeof(size_t));
    return errVal;
}

static int get_secret_input(const char *prompt, char *userInput,
                            size_t *passwordLen)
{
    /*
     * The following function is adapted from the char* getpass(const char*)
     * function from p.350 of "Advanced Programming in the UNIX Environment"
     * by W. Richard Stevens (ISBN 0201563177)
     */

    sigset_t sig, sigsave;
    struct termios term, termsave;
    FILE *fp;
    int c;
    size_t len;
    int errVal = 0;

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

    len = 0;
    while ((c = getc(fp)) != EOF && c != '\n') {
        if (len < PASSWORD_LENGTH_MAX) {
            userInput[len++] = (char)c;
        }
        else {
            len = PASSWORD_LENGTH_MAX + 1;
        }
    }
    putc('\n', fp);

    tcsetattr(fileno(fp), TCSAFLUSH, &termsave);
    sigprocmask(SIG_SETMASK, &sigsave, NULL);
    fclose(fp);

    if (len == PASSWORD_LENGTH_MAX + 1) {
        ERROR(isErr, errVal, "Password can be at most %d characters long",
              PASSWORD_LENGTH_MAX);
    }
    *passwordLen = len;

isErr:
    scrub_memory(&c, sizeof(int));
    scrub_memory(&len, sizeof(size_t));
    return errVal;
}
