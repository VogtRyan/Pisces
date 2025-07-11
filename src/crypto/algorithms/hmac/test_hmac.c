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
#include "crypto/algorithms/hmac/hmac.h"
#include "crypto/test/framework.h"
#include "crypto/test/hex.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("HMAC");

struct hmac_test {
    chf_algorithm hashalg;
    const char *key;
    const char *msg;
    const char *digest;
};

static void run_hmac_test(const struct hmac_test *test);
static void run_parsed_hmac_test(chf_algorithm hashalg, const byte *key,
                                 size_t key_len, const byte *msg,
                                 size_t msg_len, const byte *digest,
                                 size_t digest_len);

/* HMAC test vectors from FIPS documents and NIST examples */
static const struct hmac_test official_tests[] = {
    /* FIPS 198, A.1, SHA-1 with 64-Byte Key */
    {
        .hashalg = CHF_ALG_SHA1,
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .msg = "53616D706C65202331",
        .digest = "4F4CA3D5D68BA7CC0A1208C9C61E9C5DA0403C0A",
    },

    /* FIPS 198, A.2, SHA-1 with 20-Byte Key */
    {
        .hashalg = CHF_ALG_SHA1,
        .key = "303132333435363738393A3B3C3D3E3F40414243",
        .msg = "53616D706C65202332",
        .digest = "0922D3405FAA3D194F82A45830737D5CC6C75D24",
    },

    /* FIPS 198, A.3, SHA-1 with 100-Byte Key */
    {
        .hashalg = CHF_ALG_SHA1,
        .key = "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E"
               "6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D"
               "8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABAC"
               "ADAEAFB0B1B2B3",
        .msg = "53616D706C65202333",
        .digest = "BCF41EAB8BB2D802F3D05CAF7CB092ECF8D1A3AA",
    },

    /* FIPS 198, A.4, SHA-1 with 49-Byte Key, Truncated to 12-Byte HMAC */
    {
        .hashalg = CHF_ALG_SHA1,
        .key = "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E"
               "8F909192939495969798999A9B9C9D9E9FA0",
        .msg = "53616D706C65202334",
        .digest = "9EA886EFE268DBECCE420C75",
    },

    /*
     * NIST CAVP Test Vectors for Keyed-Hash Message Authentication Code
     * (HMAC), example vector labelled Count=45, Klen=10, Tlen=20. Key size is
     * smaller than block size.
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .key = "59785928D72516E31272",
        .msg =
            "A3CE8899DF1022E8D2D539B47BF0E309C66F84095E21438EC355BF119CE5FDCB4"
            "E73A619CDF36F25B369D8C38FF419997F0C59830108223606E31223483FD39EDE"
            "AA4D3F0D21198862D239C9FD26074130FF6C86493F5227AB895C8F244BD42C7AF"
            "CE5D147A20A590798C68E708E964902D124DADECDBDA9DBD0051ED710E9BF",
        .digest = "3C8162589AAFAEE024FC9A5CA50DD2336FE3EB28",
    },

    /*
     * NIST CAVP Test Vectors for Keyed-Hash Message Authentication Code
     * (HMAC), example vector labelled Count=165, Klen=64, Tlen=20. Key size is
     * equal to block size.
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .key =
            "B9575F4D5ECC0F4F62E4A0556BB89464BA97D4570E55ACD4C5E5177E452A3D6C9"
            "A0B3ADB60C6211FE48640E08637A6826299E3E52F930F4F66CB0EA6A77311E3",
        .msg =
            "8C8387F4AE2CA1A6DD13D29E93580B1CDF6268DA66CF589CA8B1FF0884F7D8B8F"
            "E299F8E41596E47E0562653612210E4FCA6C446A0A54A6E37EF80D52BD7BB8729"
            "E6B17625D197159EA98622235223C316367FD5B03A3C8145F2F210C910D000942"
            "38757627E63379E75BBB3E0D08CE1B47961309D7876FC59211C60678C5F4C",
        .digest = "15AF23331648171499B58042DBE7B2D5DF72D152",
    },

    /*
     * NIST CAVP Test Vectors for Keyed-Hash Message Authentication Code
     * (HMAC), example vector labelled Count=225, Klen=70, Tlen=20. Key size is
     * larger than block size.
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .key = "F0DAE6D8753076B1895C01262CA9B57633EB28B3F963A7C752E2CBB4C0314C"
               "20EAB11A10493FAAF4255A8EE4C0884929D1F561FF335EB699DF2D116618E6"
               "0093E5C1E2D1C499",
        .msg =
            "61CB9E1F1E4B3A3B3BDFF8CD5F24566B987F75C8A05377855F772B49B0E7EC136"
            "8B9C6CF9553DB2803DC059E05F0BDD871983C3BED79DFBB694BD0F1ED8DE36E95"
            "77BE50DA313D13124215A93A4BB7CCF4F57793CC28ED43BF7E9B68FEF7D125EFE"
            "ECEC9754B28A271FB6E16899D0BEF287E6DF7C5C867C569F6D4D66B8B7EE0",
        .digest = "62AC956ADA19F04BE50C23F2328A32477CD58FB9",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA-1, first sample, with message: "Sample message for
     * keylen=blocklen".
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B"
               "6C656E",
        .digest = "5FD596EE78D5553C8FF4E72D266DFD192366DA29",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA-1, second sample, with message: "Sample message for
     * keylen<blocklen".
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .key = "000102030405060708090A0B0C0D0E0F10111213",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B"
               "6C656E",
        .digest = "4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA-1, third sample, with message: "Sample message for
     * keylen=blocklen" (note: the input message doesn't accurately describe
     * the test, which has a key length larger than the block length of SHA-1).
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"
               "1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D"
               "3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C"
               "5D5E5F60616263",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B"
               "6C656E",
        .digest = "2D51B2F7750E410584662E38F133435F4C4FD42A",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA-1, fourth sample, with message: "Sample message for
     * keylen<blocklen, with truncated tag".
     */
    {
        .hashalg = CHF_ALG_SHA1,
        .key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"
               "1F202122232425262728292A2B2C2D2E2F30",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B"
               "6C656E2C2077697468207472756E636174656420746167",
        .digest = "FE3529565CD8E28C5FA79EAC",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA3-512, Sample #1, with message: "Sample message for
     * keylen<blocklen".
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B"
               "6C656E",
        .digest =
            "4EFD629D6C71BF86162658F29943B1C308CE27CDFA6DB0D9C3CE81763F9CBCE5F"
            "7EBE9868031DB1A8F8EB7B6B95E5C5E3F657A8996C86A2F6527E307F0213196",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA3-512, Sample #2, with message: "Sample message for
     * keylen=blocklen".
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"
               "1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D"
               "3E3F4041424344454647",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B"
               "6C656E",
        .digest =
            "544E257EA2A3E5EA19A590E6A24B724CE6327757723FE2751B75BF007D80F6B36"
            "0744BF1B7A88EA585F9765B47911976D3191CF83C039F5FFAB0D29CC9D9B6DA",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA3-512, Sample #3, with message: "Sample message for
     * keylen>blocklen".
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"
               "1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D"
               "3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C"
               "5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B"
               "7C7D7E7F8081828384858687",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3E626C6F636B"
               "6C656E",
        .digest =
            "5F464F5E5B7848E3885E49B2C385F0694985D0E38966242DC4A5FE3FEA4B37D46"
            "B65CECED5DCF59438DD840BAB22269F0BA7FEBDB9FCF74602A35666B2A32915",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA3-512, Sample #4, with message: "Sample message for
     * keylen<blocklen, with truncated tag".
     */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B"
               "6C656E2C2077697468207472756E636174656420746167",
        .digest =
            "7BB06D859257B25CE73CA700DF34C5CBEF5C898BAC91029E0B27975D4E526A08",
    },
};

/*
 * Custom test vectors. These tests are not official, but they have been
 * verified against two other independent implementations of HMAC:
 *
 * - LibreSSL 4.1.0 libcrypto implementation of HMAC in C
 * - BouncyCastle 1.81 implementation of HMAC in Java
 */
static const struct hmac_test custom_tests[] = {
    /* HMAC-SHA1, empty key and message */
    {
        .hashalg = CHF_ALG_SHA1,
        .key = "",
        .msg = "",
        .digest = "FBDB1D1B18AA6C08324B7D64B71FB76370690E1D",
    },

    /* HMAC-SHA1, key is one block, empty message */
    {
        .hashalg = CHF_ALG_SHA1,
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .msg = "",
        .digest = "60BF8C95C85CFA61279A2B9B079AA19D7FA5F31A",
    },

    /* HMAC-SHA1, empty key, message is one block */
    {
        .hashalg = CHF_ALG_SHA1,
        .key = "",
        .msg =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .digest = "BD466286495DAB05EA52B570E0047E0AB17B0D8D",
    },

    /* HMAC-SHA3-512, empty key, empty message */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .key = "",
        .msg = "",
        .digest =
            "CBCF45540782D4BC7387FBBF7D30B3681D6D66CC435CAFD82546B0FCE96B367EA"
            "79662918436FBA442E81A01D0F9592DFCD30F7A7A8F1475693D30BE4150CA84",
    },

    /* HMAC-SHA3-512, key is one block, empty message */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"
               "1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D"
               "3E3F4041424344454647",
        .msg = "",
        .digest =
            "AE200D280CBAA355C0E99F30E0ABB86173A58A4FC747860B87A2CC7D356C25525"
            "290792A8E5EE9E02B437BDA16C47AE234EEB8F70891AB8B640B6AA1F564B6F3",
    },

    /* HMAC-SHA3-512, empty key, message is one block */
    {
        .hashalg = CHF_ALG_SHA3_512,
        .key = "",
        .msg = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"
               "1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D"
               "3E3F4041424344454647",
        .digest =
            "09726AEAB10BDE6722DD09BACD431E3B2FFEBCF545226AF92868407D55B97920E"
            "F56F0665E693956D8400662DAE7D3044D5C1123999F264ED47843D19716AF3C",
    },
};

int main(void)
{
    size_t i;

    for (i = 0; i < sizeof(official_tests) / sizeof(struct hmac_test); i++) {
        run_hmac_test(&official_tests[i]);
    }

    for (i = 0; i < sizeof(custom_tests) / sizeof(struct hmac_test); i++) {
        run_hmac_test(&custom_tests[i]);
    }

    TEST_CONCLUDE();
}

static void run_hmac_test(const struct hmac_test *test)
{
    byte *key, *msg, *digest;
    size_t key_len, msg_len, digest_len;

    hex_to_bytes(test->key, &key, &key_len);
    hex_to_bytes(test->msg, &msg, &msg_len);
    hex_to_bytes(test->digest, &digest, &digest_len);

    run_parsed_hmac_test(test->hashalg, key, key_len, msg, msg_len, digest,
                         digest_len);

    free(key);
    free(msg);
    free(digest);
}

static void run_parsed_hmac_test(chf_algorithm hashalg, const byte *key,
                                 size_t key_len, const byte *msg,
                                 size_t msg_len, const byte *digest,
                                 size_t digest_len)
{
    struct hmac_ctx *ctx;
    byte actual[HMAC_MAX_DIGEST_SIZE];

    ctx = hmac_alloc(hashalg);
    ASSERT(digest_len <= hmac_digest_size(ctx),
           "HMAC test digest larger than digest size");

    memset(actual, 0, digest_len);
    hmac_single(ctx, key, key_len, msg, msg_len, actual);
    TEST_ASSERT(memcmp(actual, digest, digest_len) == 0);

    hmac_free_scrub(ctx);
}
