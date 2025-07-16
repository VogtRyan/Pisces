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

#define MESSAGE_ENCRYPT ("Enter a password to encrypt this file: ")
#define MESSAGE_CONFIRM ("Reenter the password to encrypt this file: ")
#define MESSAGE_DECRYPT ("Enter the password to decrypt this file: ")

#define MESSAGE_TOO_LONG ("Password can be at most %d characters long")
#define MESSAGE_NO_MATCH ("Passwords do not match")

static FILE *open_terminal(void);
static void close_terminal(FILE *fp_terminal);

static int read_secret_input_line(char *line, size_t *line_len,
                                  const char *prompt, FILE *fp_terminal);
static int read_input_line(char *line, size_t *line_len, FILE *fp_terminal);

int password_prompt_encryption(char *password, size_t *password_len)
{
    FILE *fp_terminal;
    char input1[PASSWORD_LENGTH_MAX];
    char input2[PASSWORD_LENGTH_MAX];
    size_t len1, len2;
    int errval = 0;

    fp_terminal = open_terminal();
    if (read_secret_input_line(input1, &len1, MESSAGE_ENCRYPT, fp_terminal)) {
        ERROR_GOTO(done, errval, MESSAGE_TOO_LONG, PASSWORD_LENGTH_MAX);
    }
    if (read_secret_input_line(input2, &len2, MESSAGE_CONFIRM, fp_terminal)) {
        ERROR_GOTO(done, errval, MESSAGE_TOO_LONG, PASSWORD_LENGTH_MAX);
    }
    if (len1 != len2 || memcmp(input1, input2, len1) != 0) {
        ERROR_GOTO(done, errval, MESSAGE_NO_MATCH);
    }
    if (ferror(fp_terminal)) {
        /*
         * close_terminal() is responsible for handling the error. But, we
         * cannot copy into the caller's memory if close_terminal() is going to
         * see the terminal's error flag.
         */
        ERROR_GOTO_SILENT(done, errval);
    }

    memcpy(password, input1, len1);
    *password_len = len1;

done:
    scrub_memory(input1, sizeof(input1));
    scrub_memory(input2, sizeof(input2));
    scrub_memory(&len1, sizeof(len1));
    scrub_memory(&len2, sizeof(len2));
    close_terminal(fp_terminal);
    return errval;
}

int password_prompt_decryption(char *password, size_t *password_len)
{
    FILE *fp_terminal;
    char input[PASSWORD_LENGTH_MAX];
    size_t len;
    int errval = 0;

    fp_terminal = open_terminal();
    if (read_secret_input_line(input, &len, MESSAGE_DECRYPT, fp_terminal)) {
        ERROR_GOTO(done, errval, MESSAGE_TOO_LONG, PASSWORD_LENGTH_MAX);
    }
    if (ferror(fp_terminal)) {
        ERROR_GOTO_SILENT(done, errval);
    }

    memcpy(password, input, len);
    *password_len = len;

done:
    scrub_memory(input, sizeof(input));
    scrub_memory(&len, sizeof(len));
    close_terminal(fp_terminal);
    return errval;
}

int password_copy(char *password, size_t *password_len,
                  const char *provided_password)
{
    size_t len;

    /* Portable replacement for strnlen, for POSIX-1.2001 compatibility */
    len = 0;
    while (len < PASSWORD_LENGTH_MAX) {
        if (provided_password[len] == '\0') {
            break;
        }
        len++;
    }
    if (provided_password[len] != '\0') {
        ERROR_RETURN(MESSAGE_TOO_LONG, PASSWORD_LENGTH_MAX);
    }

    memcpy(password, provided_password, len);
    *password_len = len;
    return 0;
}

static FILE *open_terminal(void)
{
    FILE *fp;

    fp = fopen(ctermid(NULL), "r+");
    if (fp == NULL) {
        FATAL_ERROR("Could not open terminal for reading");
    }
    return fp;
}

static void close_terminal(FILE *fp_terminal)
{
    int errflag;

    errflag = ferror(fp_terminal);
    fclose(fp_terminal);
    if (errflag) {
        FATAL_ERROR("Terminal stream error indicator set");
    }
}

/*
 * A return of 0 indicates only that the input password was not too long.
 * Caller will still have to check ferror() to determine if EOF was encountered
 * as an error condition instead of an actual EOF.
 */
static int read_secret_input_line(char *line, size_t *line_len,
                                  const char *prompt, FILE *fp_terminal)
{
    /*
     * The following function is adapted from the char* getpass(const char*)
     * function from p.350 of "Advanced Programming in the UNIX Environment"
     * by W. Richard Stevens (ISBN 0201563177).
     */

    struct termios term, termsave;
    sigset_t sig, sigsave;
    int ret;

    fprintf(fp_terminal, "%s", prompt);
    setbuf(fp_terminal, NULL);

    sigemptyset(&sig);
    sigaddset(&sig, SIGINT);
    sigaddset(&sig, SIGTSTP);
    sigprocmask(SIG_BLOCK, &sig, &sigsave);

    tcgetattr(fileno(fp_terminal), &termsave);
    term = termsave;
    term.c_lflag &= (tcflag_t)(~(ECHO | ECHOE | ECHOK | ECHONL));
    tcsetattr(fileno(fp_terminal), TCSAFLUSH, &term);

    ret = read_input_line(line, line_len, fp_terminal);

    tcsetattr(fileno(fp_terminal), TCSAFLUSH, &termsave);
    sigprocmask(SIG_SETMASK, &sigsave, NULL);
    return ret;
}

static int read_input_line(char *line, size_t *line_len, FILE *fp_terminal)
{
    int c;
    int ret = 0;

    *line_len = 0;
    while (1) {
        c = getc(fp_terminal);
        if (c == EOF || c == '\n') {
            break;
        }
        if (*line_len < PASSWORD_LENGTH_MAX) {
            line[(*line_len)++] = (char)c;
        }
        else {
            ret = -1;
        }
    }
    putc('\n', fp_terminal);

    scrub_memory(&c, sizeof(c));
    return ret;
}
