# Copyright (c) 2008-2025 Ryan Vogt <rvogt.ca@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

.POSIX:

CC    = cc
BUILD = release
CPRNG = arc4random

PREFIX         = /usr/local
INSTALL_BIN    = ${PREFIX}/bin
INSTALL_MAN    = ${PREFIX}/man/man1

# Standards:
# - C99
# - POSIX.1-2001, with the exception of optional support for the arc4random
#   family of functions
CFLAGS.COMMON = -Wall -Wextra -Wpedantic -std=c99 -D_POSIX_C_SOURCE=200112L

CFLAGS.BUILD.release = -O2
CFLAGS.BUILD.strict  = -O2 -Werror
CFLAGS.BUILD.debug   = -O0 -g -DDEBUGGING

CFLAGS.CPRNG.arc4random =
CFLAGS.CPRNG.dev        = -DPISCES_NO_ARC4RANDOM # Use /dev/random instead

IGNORE_FAILED_TESTS.BUILD.release =
IGNORE_FAILED_TESTS.BUILD.strict  =
IGNORE_FAILED_TESTS.BUILD.debug   = -
IGNORE_FAILED_TESTS               = ${IGNORE_FAILED_TESTS.BUILD.${BUILD}}

CFLAGS  = ${CFLAGS.COMMON} ${CFLAGS.CPRNG.${CPRNG}}${CFLAGS.BUILD.${BUILD}}
LDFLAGS = ${CFLAGS}

BINDIR = ./bin
MANDIR = ./man

.PHONY:
.PHONY: default all userprogs install man generate test clean deps
.SUFFIXES:
.SUFFIXES: .c .o

.c.o:
	${CC} -Isrc/ -c ${CFLAGS} -o $@ $<

##
# Full-project build options
##

default: test userprogs
all: generate test userprogs
userprogs: ${BINDIR}/pisces ${BINDIR}/pwgen

##
# Installation
##

install: default
	@if [ ! -d ${INSTALL_BIN}/ ] ; then \
	  echo Missing installation directory ${INSTALL_BIN}/ ; \
	  false ; fi
	@if [ ! -d ${INSTALL_MAN}/ ] ; then \
	  echo Missing manual installation directory ${INSTALL_MAN}/ ; \
 	  false ; fi
	cp ${BINDIR}/pisces ${INSTALL_BIN}/pisces
	cp ${BINDIR}/pwgen ${INSTALL_BIN}/pwgen
	cp ${MANDIR}/pisces.1 ${INSTALL_MAN}/pisces.1
	cp ${MANDIR}/pwgen.1 ${INSTALL_MAN}/pwgen.1

##
# View the manuals
##

man:
	man ${MANDIR}/pisces.1
	man ${MANDIR}/pwgen.1

##
# Code generation
##

generate: ${BINDIR}/generate_aes ${BINDIR}/generate_sha3

##
# crypto/primitives/aes/generate_aes
##

GENERATE_AES_OBJS = src/crypto/primitives/aes/generate_aes.o

${BINDIR}/generate_aes: ${GENERATE_AES_OBJS}
	${CC} ${LDFLAGS} -o $@ ${GENERATE_AES_OBJS}

##
# crypto/generate/generate_sha3
##

GENERATE_SHA3_OBJS = src/crypto/primitives/sha3/generate_sha3.o

${BINDIR}/generate_sha3: ${GENERATE_SHA3_OBJS}
	${CC} ${LDFLAGS} -o $@ ${GENERATE_SHA3_OBJS}

##
# Tests
##

test: ${BINDIR}/test_aes_ecb ${BINDIR}/test_aes_cbc ${BINDIR}/test_sha1 \
  ${BINDIR}/test_sha3 ${BINDIR}/test_hmac ${BINDIR}/test_pbkdf2

##
# crypto/primitives/aes/test_aes_ecb
##

TEST_AES_ECB_OBJS = src/crypto/primitives/aes/test_aes_ecb.o \
  src/crypto/primitives/aes/aes_ecb.o src/crypto/test/hex.o

${BINDIR}/test_aes_ecb: ${TEST_AES_ECB_OBJS}
	${CC} ${LDFLAGS} -o $@ ${TEST_AES_ECB_OBJS}
	${IGNORE_FAILED_TESTS}@${BINDIR}/test_aes_ecb

##
# crypto/primitives/aes/test_aes_cbc
##

TEST_AES_CBC_OBJS = src/crypto/primitives/aes/test_aes_cbc.o \
  src/crypto/primitives/aes/aes_cbc.o src/crypto/primitives/aes/aes_ecb.o \
  src/crypto/test/hex.o

${BINDIR}/test_aes_cbc: ${TEST_AES_CBC_OBJS}
	${CC} ${LDFLAGS} -o $@ ${TEST_AES_CBC_OBJS}
	${IGNORE_FAILED_TESTS}@${BINDIR}/test_aes_cbc

##
# crypto/primitives/sha1/test_sha1
##

TEST_SHA1_OBJS = src/crypto/primitives/sha1/test_sha1.o \
  src/crypto/primitives/sha1/sha1.o src/crypto/test/hex.o

${BINDIR}/test_sha1: ${TEST_SHA1_OBJS}
	${CC} ${LDFLAGS} -o $@ ${TEST_SHA1_OBJS}
	${IGNORE_FAILED_TESTS}@${BINDIR}/test_sha1

##
# crypto/primitives/sha3/test_sha3
##

TEST_SHA3_OBJS = src/crypto/primitives/sha3/test_sha3.o \
  src/crypto/primitives/sha3/sha3.o src/crypto/test/hex.o

${BINDIR}/test_sha3: ${TEST_SHA3_OBJS}
	${CC} ${LDFLAGS} -o $@ ${TEST_SHA3_OBJS}
	${IGNORE_FAILED_TESTS}@${BINDIR}/test_sha3

##
# crypto/algorithms/hmac/test_hmac
##

TEST_HMAC_OBJS = src/crypto/algorithms/hmac/test_hmac.o \
  src/crypto/algorithms/hmac/hmac.o src/crypto/abstract/chf.o \
  src/crypto/primitives/sha1/sha1.o src/crypto/primitives/sha3/sha3.o \
  src/crypto/test/hex.o

${BINDIR}/test_hmac: ${TEST_HMAC_OBJS}
	${CC} ${LDFLAGS} -o $@ ${TEST_HMAC_OBJS}
	${IGNORE_FAILED_TESTS}@${BINDIR}/test_hmac

##
# crypto/algorithms/pbkdf2/test_pbkdf2
##

TEST_PBKDF2_OBJS = src/crypto/algorithms/pbkdf2/test_pbkdf2.o \
  src/crypto/algorithms/pbkdf2/pbkdf2.o src/crypto/algorithms/hmac/hmac.o \
  src/crypto/abstract/chf.o src/crypto/primitives/sha1/sha1.o \
  src/crypto/primitives/sha3/sha3.o src/crypto/test/hex.o

${BINDIR}/test_pbkdf2: ${TEST_PBKDF2_OBJS}
	${CC} ${LDFLAGS} -o $@ ${TEST_PBKDF2_OBJS}
	${IGNORE_FAILED_TESTS}@${BINDIR}/test_pbkdf2

##
# pisces/
##

PISCES_OBJS = src/crypto/abstract/cprng.o src/crypto/abstract/kdf.o \
  src/crypto/abstract/chf.o src/crypto/abstract/cipher.o \
  src/crypto/algorithms/hmac/hmac.o src/crypto/algorithms/pbkdf2/pbkdf2.o \
  src/crypto/algorithms/pkcs7/pkcs7_padding.o \
  src/crypto/primitives/sha3/sha3.o src/crypto/primitives/sha1/sha1.o \
  src/crypto/primitives/aes/aes_cbc.o src/crypto/primitives/aes/aes_ecb.o \
  src/pisces/password.o src/pisces/iowrap.o src/pisces/holdbuf.o \
  src/pisces/version.o src/pisces/encryption.o src/pisces/pisces.o

${BINDIR}/pisces: ${PISCES_OBJS}
	${CC} ${LDFLAGS} -o $@ ${PISCES_OBJS}

##
# pwgen/
##

PWGEN_OBJS = src/pwgen/pwgen.o src/pwgen/ascii.o src/pwgen/hex.o \
  src/pwgen/usq.o src/crypto/abstract/cprng.o

${BINDIR}/pwgen: ${PWGEN_OBJS}
	${CC} ${LDFLAGS} -o $@ ${PWGEN_OBJS}

##
# Clean: remove all object files
##

clean:
	find src -name '*.o' -exec rm -f {} ';'

##
# Deps: build inference prerequisites for .c.o
##

deps:
	@for srcfile in $$(find src -name '*.c') ; do           \
	  objfile=$$(echo $${srcfile} | sed -e 's/\.c$$/\.o/'); \
	  ${CC} -Isrc/ -MM -MT $${objfile} $${srcfile};         \
	done

##
# Inference rules
##

src/crypto/abstract/cprng.o: src/crypto/abstract/cprng.c \
  src/crypto/abstract/cprng.h src/common/bytetype.h \
  src/common/errorflow.h src/common/scrub.h
src/crypto/abstract/kdf.o: src/crypto/abstract/kdf.c \
  src/crypto/abstract/kdf.h src/common/bytetype.h src/common/errorflow.h \
  src/common/scrub.h src/crypto/abstract/chf.h \
  src/crypto/algorithms/pbkdf2/pbkdf2.h
src/crypto/abstract/chf.o: src/crypto/abstract/chf.c \
  src/crypto/abstract/chf.h src/common/bytetype.h src/common/errorflow.h \
  src/common/scrub.h src/crypto/primitives/sha1/sha1.h \
  src/crypto/primitives/sha3/sha3.h
src/crypto/abstract/cipher.o: src/crypto/abstract/cipher.c \
  src/crypto/abstract/cipher.h src/common/bytetype.h \
  src/common/errorflow.h src/common/scrub.h \
  src/crypto/algorithms/pkcs7/pkcs7_padding.h \
  src/crypto/primitives/aes/aes_cbc.h
src/crypto/test/hex.o: src/crypto/test/hex.c src/crypto/test/hex.h \
  src/common/bytetype.h src/common/errorflow.h
src/crypto/algorithms/hmac/hmac.o: src/crypto/algorithms/hmac/hmac.c \
  src/crypto/algorithms/hmac/hmac.h src/common/bytetype.h \
  src/crypto/abstract/chf.h src/common/errorflow.h src/common/scrub.h
src/crypto/algorithms/hmac/test_hmac.o: \
  src/crypto/algorithms/hmac/test_hmac.c src/common/bytetype.h \
  src/common/errorflow.h src/crypto/abstract/chf.h \
  src/crypto/algorithms/hmac/hmac.h src/crypto/test/framework.h \
  src/crypto/test/hex.h
src/crypto/algorithms/pbkdf2/test_pbkdf2.o: \
  src/crypto/algorithms/pbkdf2/test_pbkdf2.c src/common/bytetype.h \
  src/common/errorflow.h src/crypto/abstract/chf.h \
  src/crypto/algorithms/pbkdf2/pbkdf2.h src/crypto/test/framework.h \
  src/crypto/test/hex.h
src/crypto/algorithms/pbkdf2/pbkdf2.o: \
  src/crypto/algorithms/pbkdf2/pbkdf2.c \
  src/crypto/algorithms/pbkdf2/pbkdf2.h src/common/bytetype.h \
  src/crypto/abstract/chf.h src/common/errorflow.h src/common/scrub.h \
  src/crypto/algorithms/hmac/hmac.h src/crypto/machine/endian.h
src/crypto/algorithms/pkcs7/pkcs7_padding.o: \
  src/crypto/algorithms/pkcs7/pkcs7_padding.c \
  src/crypto/algorithms/pkcs7/pkcs7_padding.h src/common/bytetype.h \
  src/common/errorflow.h
src/crypto/primitives/sha3/generate_sha3.o: \
  src/crypto/primitives/sha3/generate_sha3.c
src/crypto/primitives/sha3/test_sha3.o: \
  src/crypto/primitives/sha3/test_sha3.c src/common/bytetype.h \
  src/common/errorflow.h src/crypto/primitives/sha3/sha3.h \
  src/crypto/test/framework.h src/crypto/test/hex.h
src/crypto/primitives/sha3/sha3.o: src/crypto/primitives/sha3/sha3.c \
  src/crypto/primitives/sha3/sha3.h src/common/bytetype.h \
  src/common/errorflow.h src/common/scrub.h src/crypto/machine/endian.h
src/crypto/primitives/sha1/test_sha1.o: \
  src/crypto/primitives/sha1/test_sha1.c src/common/bytetype.h \
  src/common/errorflow.h src/crypto/primitives/sha1/sha1.h \
  src/crypto/test/framework.h src/crypto/test/hex.h
src/crypto/primitives/sha1/sha1.o: src/crypto/primitives/sha1/sha1.c \
  src/crypto/primitives/sha1/sha1.h src/common/bytetype.h \
  src/common/errorflow.h src/common/scrub.h src/crypto/machine/bitops.h \
  src/crypto/machine/endian.h
src/crypto/primitives/aes/test_aes_ecb.o: \
  src/crypto/primitives/aes/test_aes_ecb.c src/common/bytetype.h \
  src/common/errorflow.h src/crypto/primitives/aes/aes_ecb.h \
  src/crypto/test/framework.h src/crypto/test/hex.h
src/crypto/primitives/aes/aes_cbc.o: src/crypto/primitives/aes/aes_cbc.c \
  src/crypto/primitives/aes/aes_cbc.h src/common/bytetype.h \
  src/common/errorflow.h src/common/scrub.h \
  src/crypto/primitives/aes/aes_ecb.h
src/crypto/primitives/aes/aes_ecb.o: src/crypto/primitives/aes/aes_ecb.c \
  src/crypto/primitives/aes/aes_ecb.h src/common/bytetype.h \
  src/common/errorflow.h src/common/scrub.h src/crypto/machine/bitops.h \
  src/crypto/machine/endian.h
src/crypto/primitives/aes/test_aes_cbc.o: \
  src/crypto/primitives/aes/test_aes_cbc.c src/common/bytetype.h \
  src/common/errorflow.h src/crypto/primitives/aes/aes_cbc.h \
  src/crypto/test/framework.h src/crypto/test/hex.h
src/crypto/primitives/aes/generate_aes.o: \
  src/crypto/primitives/aes/generate_aes.c src/crypto/machine/endian.h \
  src/common/bytetype.h
src/pisces/password.o: src/pisces/password.c src/pisces/password.h \
  src/common/config.h src/common/bytetype.h src/common/errorflow.h \
  src/common/scrub.h
src/pisces/iowrap.o: src/pisces/iowrap.c src/pisces/iowrap.h \
  src/common/bytetype.h src/common/errorflow.h
src/pisces/holdbuf.o: src/pisces/holdbuf.c src/pisces/holdbuf.h \
  src/common/bytetype.h src/common/errorflow.h src/common/scrub.h
src/pisces/version.o: src/pisces/version.c src/pisces/version.h \
  src/crypto/abstract/chf.h src/common/bytetype.h \
  src/crypto/abstract/cipher.h src/crypto/abstract/kdf.h \
  src/common/errorflow.h
src/pisces/encryption.o: src/pisces/encryption.c src/pisces/encryption.h \
  src/common/bytetype.h src/common/errorflow.h src/common/scrub.h \
  src/crypto/abstract/chf.h src/crypto/abstract/cipher.h \
  src/crypto/abstract/cprng.h src/crypto/abstract/kdf.h \
  src/pisces/holdbuf.h src/pisces/iowrap.h src/pisces/version.h
src/pisces/pisces.o: src/pisces/pisces.c src/pisces/encryption.h \
  src/pisces/password.h src/common/config.h src/pisces/version.h \
  src/crypto/abstract/chf.h src/common/bytetype.h \
  src/crypto/abstract/cipher.h src/crypto/abstract/kdf.h \
  src/common/errorflow.h src/common/scrub.h
src/pwgen/hex.o: src/pwgen/hex.c src/pwgen/hex.h src/common/bytetype.h \
  src/common/errorflow.h src/common/scrub.h src/crypto/abstract/cprng.h
src/pwgen/ascii.o: src/pwgen/ascii.c src/pwgen/ascii.h \
  src/common/bytetype.h src/common/errorflow.h src/common/scrub.h \
  src/crypto/abstract/cprng.h
src/pwgen/pwgen.o: src/pwgen/pwgen.c src/pwgen/ascii.h src/pwgen/hex.h \
  src/pwgen/usq.h src/common/config.h src/common/errorflow.h \
  src/common/scrub.h src/common/bytetype.h
src/pwgen/usq.o: src/pwgen/usq.c src/pwgen/usq.h src/common/bytetype.h \
  src/common/errorflow.h src/common/scrub.h src/crypto/abstract/cprng.h
