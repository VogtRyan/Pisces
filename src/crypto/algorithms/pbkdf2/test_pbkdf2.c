/*
 * Copyright (c) 2023-2025 Ryan Vogt <rvogt.ca@gmail.com>
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

#include "common/bytetype.h"
#include "common/errorflow.h"
#include "crypto/abstract/chf.h"
#include "crypto/algorithms/pbkdf2/pbkdf2.h"
#include "crypto/test/framework.h"
#include "crypto/test/hex.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("PBKDF2");

struct pbkdf2_test {
    chf_algorithm hashalg;
    unsigned int iteration_count;
    const char *password;
    const char *salt;
    const char *derived_key;
};

static void run_pbkdf2_test(const struct pbkdf2_test *test);
static void run_parsed_pbkdf2_test(chf_algorithm hashalg,
                                   unsigned int iteration_count,
                                   const byte *password, size_t password_len,
                                   const byte *salt, size_t salt_len,
                                   const byte *derived_key,
                                   size_t derived_key_len);

/*
 * Official test vectors from RFC 6070. The fourth test vector, with an
 * iteration count of 16777216, is slow and unnecessary.
 */
#ifndef RUN_RFC_6070_TEST_VECTOR_FOUR
#define RUN_RFC_6070_TEST_VECTOR_FOUR (0)
#endif
static const struct pbkdf2_test official_tests[] = {
    /* RFC 6070, first test vector, with P="password" and S="salt" */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 1,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derived_key = "0C60C80F961F0E71F3A9B524AF6012062FE037A6",
    },

    /* RFC 6070, second test vector, with P="password" and S="salt" */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 2,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derived_key = "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957",
    },

    /* RFC 6070, third test vector, with P="password" and S="salt" */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 4096,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derived_key = "4B007901B765489ABEAD49D926F721D065A429C1",
    },

#if RUN_RFC_6070_TEST_VECTOR_FOUR
    /*
     * RFC 6070, fourth test vector, with P="password" and S="salt", and a very
     * high iteration count.
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 16777216,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derived_key = "EEFE3D61CD4DA4E4E9945B3D6BA2158C2634E984",
    },
#endif /* RUN_RFC_6070_TEST_VECTOR_FOUR */

    /*
     * RFC 6070, fifth test vector, with P="passwordPASSWORDpassword" and
     * S="saltSALTsaltSALTsaltSALTsaltSALTsalt".
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 4096,
        .password = "70617373776F726450415353574F524470617373776F7264",
        .salt = "73616C7453414C5473616C7453414C5473616C7453414C5473616C7453414"
                "C5473616C74",
        .derived_key = "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038",
    },

    /* RFC 6070, sixth test vector, with P="pass\0word" and S="sa\0lt" */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 4096,
        .password = "7061737300776F7264",
        .salt = "7361006C74",
        .derived_key = "56FA6AA75548099DCC37D7F03425E0C3",
    },
};

/*
 * Custom test vectors. These tests are not official, but they have been
 * verified against two other independent implementations of PBKDF2:
 *
 * - LibreSSL 4.1.0 libcrypto implementation of PBKDF2 in C
 * - BouncyCastle 1.81 implementation of PBKDF2 in Java, using a Java byte[]
 *   for the password (not a Java char[])
 *
 * A. Vectors for PBKDF2-HMAC-SHA1 and PBKDF2-HMAC-SHA3-512 with iteration
 * counts of 1 or 2. In PBKDF2, the U_i values are only XOR'ed into the derived
 * key when the iteration count is >= 2, so counts of 1 and 2 are tested as
 * edge cases.
 *
 * B. A vector for PBKDF2-HMAC-SHA3-512 with a random password, random salt,
 * and higher iteration count. There is no official test vector with this type
 * of typical-case input.
 *
 * The derived key in these vectors is always 2.5 times the digest size. As
 * such, these vectors test that: (a) the initial digest-sized portion of the
 * key is generated correctly; (b) the reset of the HMAC operation, necessary
 * to generate a second digest-sized portion, happens correctly; and, (c) the
 * truncation of the final digest-sized portion happens correctly.
 */
static const struct pbkdf2_test custom_tests[] = {
    /*
     * PBKDF2-HMAC-SHA1, 1 iteration, empty password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 1,
        .password = "",
        .salt = "",
        .derived_key =
            "1E437A1C79D75BE61E91141DAE20AFFC4892CC99ABCC3FE753887BC"
            "CC89201768068EBFDB085490014B92C9EBB267A9F2C82",
    },

    /*
     * PBKDF2-HMAC-SHA1, 1 iteration, one-block password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 1,
        .password =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .salt = "",
        .derived_key =
            "2C8F04C4BF9F17BC0BC6DD96ED8D430780FA204E7EC2BD8ECFC1563"
            "249C901AE38791DE833DA3259F772BEC8C58573636554",
    },

    /*
     * PBKDF2-HMAC-SHA1, 1 iteration, empty password, one-block salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 1,
        .password = "",
        .salt =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .derived_key =
            "694C4C2C49A953EC4A6C724BB50714C0311DF865FBBCC8ABDA1C22B"
            "D2C6824BFA3C3A6C630D880FEFC4C2C376E657C3EAAB3",
    },

    /*
     * PBKDF2-HMAC-SHA1, 2 iterations, empty password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 2,
        .password = "",
        .salt = "",
        .derived_key =
            "620C000A06FED9C10BCA11516B3AC0228D6717007C47BF78DA89306"
            "7BF0E258CFDCB80E4A378A48606B770E2D203B84EE6FC",
    },

    /*
     * PBKDF2-HMAC-SHA1, 2 iterations, one-block password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 2,
        .password =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .salt = "",
        .derived_key =
            "197DCBEF2740D70C2BA51A18ED0181EF25AAC2AAF0B16221D021C59"
            "5CE0682E0A3CDB2101DC99CD53FEE7CF0C2D8F3C4A01B",
    },

    /*
     * PBKDF2-HMAC-SHA1, 2 iterations, empty password, one-block salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .iteration_count = 2,
        .password = "",
        .salt =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .derived_key =
            "2ED70C3FC7C2408C757FE5BA404129266489877B28E30827439F445"
            "965B7BBA60C1F49E2EEE0C17601A5F77538575759BC4D",
    },

    /*
     * PBKDF2-HMAC-SHA3-512, 1 iteration, empty password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .iteration_count = 1,
        .password = "",
        .salt = "",
        .derived_key =
            "665409F49B9B46E3F4CB15476ED41D562F4BA27068BE4C324D95F25755C37EDF2"
            "3D64A31E4A35A344326DA324CCEE72CF45E5896F9BD261BA622E43B7A1A520409"
            "6FA736C55CA0A3B898EAD6275193EFEEA28E62BFFFC90F0972847DFE9DCE94234"
            "24F8D271BF9F00D4B5CA90F61E2BE39E4D78D713A5005FC96EAA56FCB96E7C34F"
            "4CAE618784A42238ED99DFB1B05529A0718520ECB0FEBCF2B675FBFA5A4C",
    },

    /*
     * PBKDF2-HMAC-SHA3-512, 1 iteration, one-block password, empty salt,
     * derived key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .iteration_count = 1,
        .password = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1"
                    "C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738"
                    "393A3B3C3D3E3F4041424344454647",
        .salt = "",
        .derived_key =
            "5907574054AB9B9901259D5A43D9DE317FA4ED5DE1FC868724C7FCD41363C916E"
            "3663F0DD3BB705286592ECA0650550FE5908730FA30BC9FE18E43AA4B3CD92D21"
            "9C2B3A4D8988E1F79D40A8E1204EC350279D1CC9E715F593F5BA7B5A8EBFF0101"
            "B86592B10FC4B6999E9985311AFA46E0DC4961EB6EFA7096C69B106353D3DA5CE"
            "7D61AA3989AAD1CF7F0EC351F22B6E7C435367AFF17EC8898A8B1F5B1089",
    },

    /*
     * PBKDF2-HMAC-SHA3-512, 1 iteration, empty password, one-block salt,
     * derived key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .iteration_count = 1,
        .password = "",
        .salt = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1"
                "E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C"
                "3D3E3F4041424344454647",
        .derived_key =
            "DDEB12984918FB9636E7D51CDDAF7B7B02893C905AF6AF4C401FAC505A4B3D7D0"
            "9D18A5ED244324D24C52B110719CD92E23FB788371C5F73A0961197A941F629A0"
            "28C5D1C8665F8B8AEF1533A8FE08910113749A22942C53F43B90FD61707631D3F"
            "802B5B6C9540C9E4C6C67E1F33CBA932479DF07F3A5569D5C35C3F6BD2919F4D3"
            "9E5547CD07F563B6FA3E7F5A1898E931DFF8F1AA7CF228B2FC0D90C99687",
    },

    /*
     * PBKDF2-HMAC-SHA3-512, 2 iterations, empty password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .iteration_count = 2,
        .password = "",
        .salt = "",
        .derived_key =
            "E0300B096B9EECC5AD2BD231A5DF623C6BE485F6F3C172ED274F6A15BDA08BA89"
            "D4A1934AF1BDEBF30C303E2E065320AB97BB17CEC1A778FF0E2A60413126376B0"
            "539CEF59B283C3CD3D3465A925222809085CEED72BCCEE9FDBF8708676813EA8B"
            "C9039F466A13E406AB9CAE9366317518B05BB701B5BD7212D590250021649013C"
            "615028ACCE305E4C7CF19CB71AAF0BF22B2F59517D93413E080CC18BFFDA",
    },

    /*
     * PBKDF2-HMAC-SHA3-512, 2 iterations, one-block password, empty salt,
     * derived key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .iteration_count = 2,
        .password = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1"
                    "C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738"
                    "393A3B3C3D3E3F4041424344454647",
        .salt = "",
        .derived_key =
            "ECEC8D4FEBD159EAAD31A924A04900DDC780A6E40EFD327494FA8E6BFF80C08BE"
            "D1A656A28F7B0B083C972C1F8FF03EC3B328A11CA343E03E1DFA3651213AF589C"
            "F306C0AF07719AA44DCF17089C94F876F9F86303806E96C28B79B2AD2CE737D85"
            "733DEF8D7DBF535DA3FFB1D788C4DEA2C998A4797308E6B683E70678D0B4E5A28"
            "EE1477A16D73711DEB52A70134869D24DB67A82F4FBC90B1522033E6AD50",
    },

    /*
     * PBKDF2-HMAC-SHA3-512, 2 iterations, empty password, one-block salt,
     * derived key 2.5 times the digest size.
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .iteration_count = 2,
        .password = "",
        .salt = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1"
                "E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C"
                "3D3E3F4041424344454647",
        .derived_key =
            "2C747171DB9217616A0598A94E37CDB56D221F246C0365A66E3E9F7E39A9F0048"
            "1E4F14125F90D7B67835DA44657DE0CEBFC35D1FEDDA485943B5BB11DE54AE4D1"
            "992CAC133E672061849262F31B53D0AC08DB870690982C9DE3A60449FB61E16E0"
            "E5D4ED6691A9D1AF8D490DCC6182A0B45A7B4FA6EFD842B67843FF03D70E32E19"
            "4DBD5F224531662492AC52B50B035F7B4AE1E146469A3CA861C171EB8B59",
    },

    /*
     * PBKDF2-HMAC-SHA3-512, "random" password and "random" salt, both 2.5
     * times the block size; derived key 2.5 times the digest size.
     *
     * The "random" data are the first 720 hexadecimal digits of pi -- the
     * first 360 as the password, the next 360 as the salt. These digits were
     * computed using the Bailey-Borwein-Plouffe (BBP) formula, and are the
     * same as those used in the Blowfish P-array and first S-box.
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .iteration_count = 255,
        .password =
            "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C894"
            "52821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B547091792"
            "16D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7"
            "C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458"
            "FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B59C30D"
            "5392AF26013C5D1B023286085F0CA417918",
        .salt = "B8DB38EF8E79DCB0603A180E6C9E0E8BB01E8A3ED71577C1BD314B2778AF2"
                "FDA55605C60E65525F3AA55AB945748986263E8144055CA396A2AAB10B6B4"
                "CC5C341141E8CEA15486AF7C72E993B3EE1411636FBC2A2BA9C55D741831F"
                "6CE5C3E169B87931EAFD6BA336C24CF5C7A325381289586773B8F48986B4B"
                "B9AFC4BFE81B6628219361D809CCFB21A991487CAC605DEC8032EF845D5DE"
                "98575B1DC262302EB651B8823893E81D396ACC50F6D6FF383F44239",
        .derived_key =
            "E8536BC9D970C8AAAD7865F6A7B0ACF04D182DC2B75B1FB26C46C2D3A0CB2FA70"
            "5E95FADD0260B7E743CD8773F77CAE56674368AB60E5E56B7A201E3CC7B848707"
            "02BAB61122ECD880E8E9DF0C5944D8F699F2C8E0C647C9F95D778B741DC80A693"
            "495CE9ABCDCBCF42AD548F68CDCA47463649C16ED5643D8D5109C339B9F11CF3C"
            "81EC0D499CC82AB8E72CBF792A11D594F15361C466306685E2208AB3697F",
    },
};

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(official_tests) / sizeof(struct pbkdf2_test); i++) {
        run_pbkdf2_test(&official_tests[i]);
    }

    for (i = 0; i < sizeof(custom_tests) / sizeof(struct pbkdf2_test); i++) {
        run_pbkdf2_test(&custom_tests[i]);
    }

    TEST_CONCLUDE();
}

static void run_pbkdf2_test(const struct pbkdf2_test *test)
{
    byte *password, *salt, *derived_key;
    size_t password_len, salt_len, derived_key_len;

    hex_to_bytes(test->password, &password, &password_len);
    hex_to_bytes(test->salt, &salt, &salt_len);
    hex_to_bytes(test->derived_key, &derived_key, &derived_key_len);

    run_parsed_pbkdf2_test(test->hashalg, test->iteration_count, password,
                           password_len, salt, salt_len, derived_key,
                           derived_key_len);

    free(password);
    free(salt);
    free(derived_key);
}

static void run_parsed_pbkdf2_test(chf_algorithm hashalg,
                                   unsigned int iteration_count,
                                   const byte *password, size_t password_len,
                                   const byte *salt, size_t salt_len,
                                   const byte *derived_key,
                                   size_t derived_key_len)
{
    byte *actual;

    actual = calloc(1, derived_key_len);
    GUARD_ALLOC(actual);

    pbkdf2_hmac(actual, derived_key_len, (const char *)password, password_len,
                salt, salt_len, iteration_count, hashalg);

    TEST_ASSERT(memcmp(actual, derived_key, derived_key_len) == 0);
    free(actual);
}
