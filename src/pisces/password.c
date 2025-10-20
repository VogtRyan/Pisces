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

#define ERROR_PASSWORD_TOO_LONG (0x01)
#define ERROR_ILLEGAL_CHAR_NULL (0x02)

#define MESSAGE_ENCRYPT "Enter a password to encrypt this file: "
#define MESSAGE_CONFIRM "Reenter the password to encrypt this file: "
#define MESSAGE_DECRYPT "Enter the password to decrypt this file: "

#define MESSAGE_TOO_LONG "Password can be at most %d characters long"
#define MESSAGE_NO_MATCH "Passwords do not match"

static FILE *open_terminal(void);
static void close_terminal(FILE *fp_terminal);

static int read_secret_input_line(byte *line, size_t *line_len,
                                  const char *prompt, FILE *fp_terminal);
static int read_input_line(byte *line, size_t *line_len, FILE *fp_terminal);

int password_prompt_encryption(byte *password, size_t *password_len)
{
    FILE *fp_terminal;
    byte input1[PASSWORD_LENGTH_MAX];
    byte input2[PASSWORD_LENGTH_MAX];
    size_t len1, len2;
    int errval = 0;

    fp_terminal = open_terminal();

    if (read_secret_input_line(input1, &len1, MESSAGE_ENCRYPT, fp_terminal)) {
        ERROR_GOTO_SILENT(done, errval);
    }
    if (read_secret_input_line(input2, &len2, MESSAGE_CONFIRM, fp_terminal)) {
        ERROR_GOTO_SILENT(done, errval);
    }
    if (len1 != len2 || memcmp(input1, input2, len1) != 0) {
        ERROR_GOTO(done, errval, MESSAGE_NO_MATCH);
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

int password_prompt_decryption(byte *password, size_t *password_len)
{
    FILE *fp_terminal;
    byte input[PASSWORD_LENGTH_MAX];
    size_t len;
    int errval = 0;

    fp_terminal = open_terminal();

    if (read_secret_input_line(input, &len, MESSAGE_DECRYPT, fp_terminal)) {
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

int password_copy(byte *password, size_t *password_len,
                  const char *provided_password)
{
    size_t len;
    int errval = 0;

    len = 0;
    while (len < PASSWORD_LENGTH_MAX) {
        if (provided_password[len] == '\0') {
            break;
        }
        else if (provided_password[len] == '\n') {
            /*
             * read_input_line() uses '\n' as its termination character, so
             * prohibit its use in all passwords.
             */
            ERROR_GOTO(done, errval,
                       "Password contains illegal newline character");
        }
        len++;
    }

    if (provided_password[len] != '\0') {
        ERROR_GOTO(done, errval, MESSAGE_TOO_LONG, PASSWORD_LENGTH_MAX);
    }

    memcpy(password, provided_password, len);
    *password_len = len;

done:
    scrub_memory(&len, sizeof(len));
    return errval;
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
    if (fp_terminal != NULL) {
        fclose(fp_terminal);
    }
}

static int read_secret_input_line(byte *line, size_t *line_len,
                                  const char *prompt, FILE *fp_terminal)
{
    /*
     * The following function is adapted from the char* getpass(const char*)
     * function from p.350 of "Advanced Programming in the UNIX Environment"
     * by W. Richard Stevens (ISBN 0201563177).
     */

    struct termios no_echo_term, orig_term;
    sigset_t blocked_sigs, orig_sig_mask;
    int ret;

    fprintf(fp_terminal, "%s", prompt);
    setbuf(fp_terminal, NULL);

    sigemptyset(&blocked_sigs);
    sigaddset(&blocked_sigs, SIGINT);
    sigaddset(&blocked_sigs, SIGTSTP);
    sigprocmask(SIG_BLOCK, &blocked_sigs, &orig_sig_mask);

    if (tcgetattr(fileno(fp_terminal), &orig_term)) {
        FATAL_ERROR("Could not get original termios attributes");
    }

    no_echo_term = orig_term;
    no_echo_term.c_lflag &= (tcflag_t)(~(ECHO | ECHOE | ECHOK | ECHONL));
    if (tcsetattr(fileno(fp_terminal), TCSAFLUSH, &no_echo_term)) {
        FATAL_ERROR("Could not set termios attributes to silent");
    }

    ret = read_input_line(line, line_len, fp_terminal);

    if (tcsetattr(fileno(fp_terminal), TCSAFLUSH, &orig_term)) {
        FATAL_ERROR("Could not restore termios attributes");
    }
    sigprocmask(SIG_SETMASK, &orig_sig_mask, NULL);

    return ret;
}

static int read_input_line(byte *line, size_t *line_len, FILE *fp_terminal)
{
    int c;
    int errval = 0;

    *line_len = 0;
    while (1) {
        c = getc(fp_terminal);
        if (c == EOF || c == '\n') {
            break;
        }
        else if (c == '\0') {
            /*
             * copy_password() uses NULL as a termination character, so
             * prohibit its use in all passwords.
             */
            errval |= ERROR_ILLEGAL_CHAR_NULL;
        }

        if (*line_len < PASSWORD_LENGTH_MAX) {
            line[*line_len] = (byte)c;
            (*line_len)++;
        }
        else {
            errval |= ERROR_PASSWORD_TOO_LONG;
        }
    }
    putc('\n', fp_terminal);

    /* Let user finish typing the entire line before reporting any errors */
    scrub_memory(&c, sizeof(c));
    if (ferror(fp_terminal)) {
        FATAL_ERROR("Terminal stream error indicator set");
    }
    else if (errval & ERROR_ILLEGAL_CHAR_NULL) {
        ERROR_RETURN("Password contains illegal NULL character");
    }
    else if (errval & ERROR_PASSWORD_TOO_LONG) {
        ERROR_RETURN(MESSAGE_TOO_LONG, PASSWORD_LENGTH_MAX);
    }
    return 0;
}
