/*
 * Copyright (c) 2011-2023 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "crypto/machine/endian.h"

#include <stdint.h>
#include <stdio.h>

/*
 * This program generates the large tables in the AES source file. S_BOX_ENC
 * must be manually defined (using the AES FIPS-197 specification); all of the
 * other tables used in aes_ecb.c are algorithmically generated.
 *
 * See aes_ecb.c for descriptions of all the tables generated.
 */

/*
 * The AES forward S-box, defined in Figure 7, "S-box: substitution values for
 * the byte xy (in hexadecimal format)", FIPS-197, p.16.
 */
static const uint8_t S_BOX_ENC[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16};

/*
 * Constructs the decryption S-Box based on the encryption S-Box, then outputs
 * both S-Boxes.
 */
static void build_dec_sbox(const uint8_t *encSBox, uint8_t *decSBox);

/*
 * Build the lookup tables that describe the single-operation combination of
 * the SubBytes() and MixColumns() operations necessary for this file (where
 * SubBytes() and MixColumns() are described in FIPS-197).
 */
static void build_sub_mix_tables(const uint8_t *encSBox,
                                 const uint8_t *decSBox);

/*
 * Builds and outputs a single SubBytes()-MixColumns() operation table using
 * the given S-Box and polynomial multipliers (the S-Box may be NULL to build
 * just a MixColumns() table).  The polyRotation constant induces a rightward
 * circular shift in the polynomials array (e.g., if polyRotation is set to 1,
 * when this function tries to look up polynomials[1], it will get the value
 * that is actually stored in polynomials[0] -- that is, it is as if you
 * rotated the polynomials array in a circular fashion).
 */
static void build_sub_mix_table(const uint8_t *sbox,
                                const uint8_t *polynomials, int polyRotation,
                                int isEncryption);

/*
 * Builds the round constant table and outputs it.
 */
static void build_rcon_table();

/*
 * Treats the two given bytes as a polynomials over GF(2^8) and multiplies them
 * together, mod m(x) = x^8 + x^4 + x^3 + x + 1.
 */
static uint8_t muly_polys(uint8_t polyA, uint8_t polyB);

/*
 * Treats the given byte as a polynomial over GF(2^8) and multiplies that
 * polynomial by x, mod m(x) = x^8 + x^4 + x^3 + x + 1.
 */
static uint8_t mult_by_x(uint8_t polynomial);

/*
 * Outputs the contents of a hexadecimal table to standard output.
 */
static void print_table(const uint8_t *table, int entries, size_t entrySize,
                        int entriesPerRow, const char *name,
                        const char *dataType);

/*
 * Print the given bytes in hexadecimal to standard output.
 */
void print_bytes(const uint8_t *bytes, size_t numBytes);

/*
 * Generates and prints the contents of the S-Boxes and the
 * SubBytes()-MixColumns() tables and round constant table defined in this
 * source file, provided that S_BOX_ENC is already defined.  The contents of
 * the encryption S-Box can be found in FIPS-197.
 */
int main()
{
    uint8_t decSBox[256];
    build_dec_sbox(S_BOX_ENC, decSBox);
    build_sub_mix_tables(S_BOX_ENC, decSBox);
    build_rcon_table();
    return 0;
}

static void build_dec_sbox(const uint8_t *encSBox, uint8_t *decSBox)
{
    int i;
    uint8_t s;

    for (i = 0; i < 256; i++) {
        s = encSBox[i];
        decSBox[s] = (uint8_t)i;
    }

    print_table(encSBox, 256, 1, 12, "S_BOX_ENC", "uint8_t");
    printf("\n");
    print_table(decSBox, 256, 1, 12, "S_BOX_DEC", "uint8_t");
    printf("\n");
}

static void build_sub_mix_tables(const uint8_t *encSBox,
                                 const uint8_t *decSBox)
{
    uint8_t polynomials[4];
    int i;

    /* Encryption polynomials as per FIPS-197 */
    polynomials[0] = 0x02;
    polynomials[1] = 0x01;
    polynomials[2] = 0x01;
    polynomials[3] = 0x03;

    /* Print encryption sub-mix tables */
    for (i = 0; i < 4; i++) {
        build_sub_mix_table(encSBox, polynomials, i, 1);
        printf("\n");
    }

    /* Decryption polynomials as per FIPS-197 */
    polynomials[0] = 0x0E;
    polynomials[1] = 0x09;
    polynomials[2] = 0x0D;
    polynomials[3] = 0x0B;

    /* Print decryption mix tables */
    for (i = 0; i < 4; i++) {
        build_sub_mix_table(NULL, polynomials, i, 0);
        printf("\n");
    }

    /* Print decryption sub-mix tables */
    for (i = 0; i < 4; i++) {
        build_sub_mix_table(decSBox, polynomials, i, 0);
        printf("\n");
    }
}

static void build_sub_mix_table(const uint8_t *sbox,
                                const uint8_t *polynomials, int polyRotation,
                                int isEncryption)
{
    uint8_t table[1024];
    char name[17];
    int i, j;

    for (i = 0; i < 256; i++) {
        for (j = 0; j < 4; j++) {
            if (sbox == NULL) {
                table[i * 4 + j] = muly_polys(
                    (uint8_t)i, polynomials[(j + 4 - polyRotation) % 4]);
            }
            else {
                table[i * 4 + j] = muly_polys(
                    sbox[i], polynomials[(j + 4 - polyRotation) % 4]);
            }
        }
    }
    snprintf(name, 17, "%sMIX_%s_POS%d", (sbox != NULL ? "SUB_" : ""),
             (isEncryption ? "ENC" : "DEC"), polyRotation);
    print_table(table, 256, 4, 6, name, "uint32_t");
}

static void build_rcon_table()
{
    uint8_t table[40];
    uint8_t poly = 0x01;
    int i;

    put_big_end_32(table, ((uint32_t)poly) << 24);
    for (i = 1; i < 10; i++) {
        poly = mult_by_x(poly);
        put_big_end_32(table + i * 4, ((uint32_t)poly) << 24);
    }

    print_table(table, 10, 4, 5, "RCON", "uint32_t");
}

static uint8_t muly_polys(uint8_t polyA, uint8_t polyB)
{
    uint8_t ret = 0;

    while (polyB != 0) {
        if (polyB & 0x01) {
            ret ^= polyA;
        }
        polyB >>= 1;
        polyA = mult_by_x(polyA);
    }

    return ret;
}

static uint8_t mult_by_x(uint8_t polynomial)
{
    if (polynomial & 0x80) {
        return (polynomial << 1) ^ 0x1B;
    }
    else {
        return (polynomial << 1);
    }
}

static void print_table(const uint8_t *table, int entries, size_t entrySize,
                        int entriesPerRow, const char *name,
                        const char *dataType)
{
    int inRow, onEntry;

    printf("static const %s %s[%d] = {\n    ", dataType, name, entries);

    inRow = 0;
    for (onEntry = 0; onEntry < entries; onEntry++) {
        print_bytes(table, entrySize);
        table += entrySize;
        if (onEntry == entries - 1) {
            printf("};\n");
        }
        else {
            printf(",");
            inRow++;
            if (inRow == entriesPerRow) {
                printf("\n    ");
                inRow = 0;
            }
            else {
                printf(" ");
            }
        }
    }
}

void print_bytes(const uint8_t *bytes, size_t numBytes)
{
    size_t i;

    printf("0x");
    for (i = 0; i < numBytes; i++) {
        printf("%02X", bytes[i]);
    }
}
