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

/*
 * Parameters for testing the output of a single invocation of the PBKDF2
 * algorithm.
 */
struct pbkdf2_test {
    chf_algorithm_t hashAlg;
    unsigned int iterationCount;
    const char *password;
    const char *salt;
    const char *derivedKey;
};

/*
 * Runs a PBKDF2 test, and asserts that the actual derived key matches the
 * expected derived key in the given test parameters.
 */
static void run_pbkdf2_test(const struct pbkdf2_test *test);

/*
 * Runs a PBKDF2 test that has been parsed from its hexadecimal string format.
 */
static void run_parsed_pbkdf2_test(chf_algorithm_t hashAlg,
                                   unsigned int iterationCount,
                                   const byte_t *password, size_t passwordLen,
                                   const byte_t *salt, size_t saltLen,
                                   const byte_t *derivedKey,
                                   size_t derivedKeyLen);

/*
 * Official test vectors (from RFC 6070) to run for PBKDF2. The fourth test
 * vector, with an iteration count of 16777216, is intentionally omitted
 * by default because of the time it takes to run.
 */
#ifndef RUN_RFC_6070_TEST_VECTOR_FOUR
#define RUN_RFC_6070_TEST_VECTOR_FOUR (0)
#endif
static const struct pbkdf2_test officialTests[] = {
    /* RFC 6070, first test vector, with P="password" and S="salt" */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 1,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derivedKey = "0C60C80F961F0E71F3A9B524AF6012062FE037A6",
    },

    /* RFC 6070, second test vector, with P="password" and S="salt" */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 2,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derivedKey = "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957",
    },

    /* RFC 6070, third test vector, with P="password" and S="salt" */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 4096,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derivedKey = "4B007901B765489ABEAD49D926F721D065A429C1",
    },

#if RUN_RFC_6070_TEST_VECTOR_FOUR
    /*
     * RFC 6070, fourth test vector, with P="password" and S="salt", and a very
     * high iteration count.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 16777216,
        .password = "70617373776F7264",
        .salt = "73616C74",
        .derivedKey = "EEFE3D61CD4DA4E4E9945B3D6BA2158C2634E984",
    },
#endif /* RUN_RFC_6070_TEST_VECTOR_FOUR */

    /*
     * RFC 6070, fifth test vector, with P="passwordPASSWORDpassword" and
     * S="saltSALTsaltSALTsaltSALTsaltSALTsalt".
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 4096,
        .password = "70617373776F726450415353574F524470617373776F7264",
        .salt = "73616C7453414C5473616C7453414C5473616C7453414C5473616C7453414"
                "C5473616C74",
        .derivedKey = "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038",
    },

    /* RFC 6070, sixth test vector, with P="pass\0word" and S="sa\0lt" */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 4096,
        .password = "7061737300776F7264",
        .salt = "7361006C74",
        .derivedKey = "56FA6AA75548099DCC37D7F03425E0C3",
    },
};

/*
 * Custom test vectors. These tests are not official, and should be treated
 * accordingly. However, they have been verified against two other
 * independent implementations of PBKDF2:
 *
 * - LibreSSL 3.9.0 libcrypto implementation of PBKDF2 in C
 * - BouncyCastle 1.78.1 implementation of PBKDF2 in Java, using a Java byte[]
 *   for the password (not a Java char[])
 *
 * The first of these vectors are designed to test edge cases of the PBKDF2
 * algorithm for both PBKDF2-HMAC-SHA1 and PBKDF2-HMAC-SHA3-512. In the PBKDF2
 * algorithm, the U_i values are only XOR'ed into the derived key when the
 * iteration count is >= 2; so, iteration counts of both 1 and 2 are presented
 * as edge cases below.
 *
 * There is also a test vector for PBKDF2-HMAC-SHA3-512 with a random password,
 * a random salt, and a higher iteration count. This test vector is included
 * due to the lack of an official test vector of this nature.
 *
 * The derived key size in these vectors is always 2.5 times the digest size,
 * to test that the first digest-sized portion of the key and subsequent
 * digest-sized portions of the key (truncated or not) are generated correctly.
 * Note: a shorter key derived with PBKDF2 is just a truncation of a longer
 * derived key, provided all the inputs to PBKDF2 aside from the derived key
 * size are the same. So, any derived key size in the test vectors greater than
 * 2 times the digest size, and not a multiple of the digest size, meets the
 * test criteria.
 */
static const struct pbkdf2_test customTests[] = {
    /*
     * PBKDF2-HMAC-SHA1, 1 iteration, empty password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 1,
        .password = "",
        .salt = "",
        .derivedKey = "1E437A1C79D75BE61E91141DAE20AFFC4892CC99ABCC3FE753887BC"
                      "CC89201768068EBFDB085490014B92C9EBB267A9F2C82",
    },

    /*
     * PBKDF2-HMAC-SHA1, 1 iteration, one-block password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 1,
        .password =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .salt = "",
        .derivedKey = "2C8F04C4BF9F17BC0BC6DD96ED8D430780FA204E7EC2BD8ECFC1563"
                      "249C901AE38791DE833DA3259F772BEC8C58573636554",
    },

    /*
     * PBKDF2-HMAC-SHA1, 1 iteration, empty password, one-block salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 1,
        .password = "",
        .salt =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .derivedKey = "694C4C2C49A953EC4A6C724BB50714C0311DF865FBBCC8ABDA1C22B"
                      "D2C6824BFA3C3A6C630D880FEFC4C2C376E657C3EAAB3",
    },

    /*
     * PBKDF2-HMAC-SHA1, 2 iterations, empty password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 2,
        .password = "",
        .salt = "",
        .derivedKey = "620C000A06FED9C10BCA11516B3AC0228D6717007C47BF78DA89306"
                      "7BF0E258CFDCB80E4A378A48606B770E2D203B84EE6FC",
    },

    /*
     * PBKDF2-HMAC-SHA1, 2 iterations, one-block password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 2,
        .password =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .salt = "",
        .derivedKey = "197DCBEF2740D70C2BA51A18ED0181EF25AAC2AAF0B16221D021C59"
                      "5CE0682E0A3CDB2101DC99CD53FEE7CF0C2D8F3C4A01B",
    },

    /*
     * PBKDF2-HMAC-SHA1, 2 iterations, empty password, one-block salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .iterationCount = 2,
        .password = "",
        .salt =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .derivedKey = "2ED70C3FC7C2408C757FE5BA404129266489877B28E30827439F445"
                      "965B7BBA60C1F49E2EEE0C17601A5F77538575759BC4D",
    },

    /*
     * PBKDF2-HMAC-SHA3-512, 1 iteration, empty password, empty salt, derived
     * key 2.5 times the digest size.
     */
    {
        .hashAlg = CHF_ALG_SHA3_512,
        .iterationCount = 1,
        .password = "",
        .salt = "",
        .derivedKey =
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
        .hashAlg = CHF_ALG_SHA3_512,
        .iterationCount = 1,
        .password = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1"
                    "C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738"
                    "393A3B3C3D3E3F4041424344454647",
        .salt = "",
        .derivedKey =
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
        .hashAlg = CHF_ALG_SHA3_512,
        .iterationCount = 1,
        .password = "",
        .salt = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1"
                "E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C"
                "3D3E3F4041424344454647",
        .derivedKey =
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
        .hashAlg = CHF_ALG_SHA3_512,
        .iterationCount = 2,
        .password = "",
        .salt = "",
        .derivedKey =
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
        .hashAlg = CHF_ALG_SHA3_512,
        .iterationCount = 2,
        .password = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1"
                    "C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738"
                    "393A3B3C3D3E3F4041424344454647",
        .salt = "",
        .derivedKey =
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
        .hashAlg = CHF_ALG_SHA3_512,
        .iterationCount = 2,
        .password = "",
        .salt = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1"
                "E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C"
                "3D3E3F4041424344454647",
        .derivedKey =
            "2C747171DB9217616A0598A94E37CDB56D221F246C0365A66E3E9F7E39A9F0048"
            "1E4F14125F90D7B67835DA44657DE0CEBFC35D1FEDDA485943B5BB11DE54AE4D1"
            "992CAC133E672061849262F31B53D0AC08DB870690982C9DE3A60449FB61E16E0"
            "E5D4ED6691A9D1AF8D490DCC6182A0B45A7B4FA6EFD842B67843FF03D70E32E19"
            "4DBD5F224531662492AC52B50B035F7B4AE1E146469A3CA861C171EB8B59",
    },

    /*
     * PBKDF2-HMAC-SHA3-512, random password and random salt, both 2.5 times
     * the block size; derived key 2.5 times the digest size.
     */
    {
        .hashAlg = CHF_ALG_SHA3_512,
        .iterationCount = 255,
        .password =
            "2A54983A106E4651A491FAB8DA3719020044EB7B51F97F955DBDCF0424A75059F"
            "13E2858E708D168ED246F3EEC90BC06E0226428BF64A18D5BFB2E50757E9282C9"
            "158040314D74405BEDCDF21438C50A2452E886758DE78CF4A340ED05BA1784863"
            "9882906940814AAE40E6B76451A98973F43359BB3A8ABBB59066EE8E402F6C8A1"
            "4380A42CDA35C95C6C910810556D08D0C78FDBC59C22DE45043689610D8502D98"
            "6274558A644B78DBC624FFD95261B92911D",
        .salt = "2AF5B36FB8426C8D2640D8CEC8D625C7808D88A29747D45B89710FA58F6E9"
                "CA02C6C2BCACC431AF04DF0564D0A4F589E66A199628465051A4ED65ACBDD"
                "AD598FFF4DDC8965A52707EBC93EC04F0A4D6086E027CFD5AD2F96EA98377"
                "747BD7BB099FF264CBB7A8BEAEE2731BCB0C18F931AD079CC84E1CEA7CD6F"
                "02D61D3EA3BF75B5228CB98E884EFA8C6A33453A9B12665B78FF5C6B91F5C"
                "234331323EAD2F5BBA1738FB25D9E5109D599522C36D6C3AC7DBD81",
        .derivedKey =
            "ADC7842BE417EE98FAD451A14AD819CD90821542DD7611C6892FA2CC36A8E63C9"
            "03F8016B4321A057E0902DF61FCC05CCE0A506B14A0ADB4DB84A0FC6DE7A65F06"
            "D9962AB0B288FFB70BF9224C594B3AC1E023D7DBAC9508E86CA65B3361775DDCC"
            "B75AF27552958459D4AF1A0D70BC1B48E4855E1FA225B47F5C5F13FE389F7F03B"
            "C62F128E95804C04213416FB0A0A1CE36EB9C14C02FD7CF5F17CD1B3D3A4",
    },
};

/*
 * Run the PBKDF2 tests and report the success rate.
 */
int main(void)
{
    size_t onTest;

    for (onTest = 0;
         onTest < sizeof(officialTests) / sizeof(struct pbkdf2_test);
         onTest++) {
        run_pbkdf2_test(&officialTests[onTest]);
    }

    for (onTest = 0; onTest < sizeof(customTests) / sizeof(struct pbkdf2_test);
         onTest++) {
        run_pbkdf2_test(&customTests[onTest]);
    }

    TEST_CONCLUDE();
}

static void run_pbkdf2_test(const struct pbkdf2_test *test)
{
    byte_t *password, *salt, *derivedKey;
    size_t passwordLen, saltLen, derivedKeyLen;

    hex_to_bytes(test->password, &password, &passwordLen);
    hex_to_bytes(test->salt, &salt, &saltLen);
    hex_to_bytes(test->derivedKey, &derivedKey, &derivedKeyLen);

    run_parsed_pbkdf2_test(test->hashAlg, test->iterationCount, password,
                           passwordLen, salt, saltLen, derivedKey,
                           derivedKeyLen);

    free(password);
    free(salt);
    free(derivedKey);
}

static void run_parsed_pbkdf2_test(chf_algorithm_t hashAlg,
                                   unsigned int iterationCount,
                                   const byte_t *password, size_t passwordLen,
                                   const byte_t *salt, size_t saltLen,
                                   const byte_t *derivedKey,
                                   size_t derivedKeyLen)
{
    byte_t *actual;
    actual = calloc(1, derivedKeyLen);
    GUARD_ALLOC(actual);

    pbkdf2_hmac(actual, derivedKeyLen, (const char *)password, passwordLen,
                salt, saltLen, iterationCount, hashAlg);

    TEST_ASSERT(memcmp(actual, derivedKey, derivedKeyLen) == 0);
    free(actual);
}
