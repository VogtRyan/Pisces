/*
 * Copyright (c) 2023-2024 Ryan Vogt <rvogt.ca@gmail.com>
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

#include <string.h>

TEST_PREAMBLE("HMAC");

/*
 * Parameters for testing the output of a single invocation of the HMAC
 * algorithm.
 */
struct hmac_test {
    chf_algorithm_t hashAlg;
    const char *key;
    const char *msg;
    const char *output;
};

/*
 * Runs an HMAC test, and asserts that the actual output matches the expected
 * output in the given test parameters.
 */
static void run_hmac_test(const struct hmac_test *test);

/*
 * Runs an HMAC test that has been parsed from its hexadecimal string format.
 * The outputLen must be less than or equal to the digest length of the of the
 * hash algorithm.
 */
static void run_parsed_hmac_test(chf_algorithm_t hashAlg, const byte_t *key,
                                 size_t keyLen, const byte_t *msg,
                                 size_t msgLen, const byte_t *output,
                                 size_t outputLen);

/*
 * All of the HMAC tests to run.
 */
static const struct hmac_test allTests[] = {
    /* FIPS 198, A.1, SHA-1 with 64-Byte Key */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .msg = "53616D706C65202331",
        .output = "4F4CA3D5D68BA7CC0A1208C9C61E9C5DA0403C0A",
    },

    /* FIPS 198, A.2, SHA-1 with 20-Byte Key */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key = "303132333435363738393A3B3C3D3E3F40414243",
        .msg = "53616D706C65202332",
        .output = "0922D3405FAA3D194F82A45830737D5CC6C75D24",
    },

    /* FIPS 198, A.3, SHA-1 with 100-Byte Key */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key = "505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E"
               "6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D"
               "8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABAC"
               "ADAEAFB0B1B2B3",
        .msg = "53616D706C65202333",
        .output = "BCF41EAB8BB2D802F3D05CAF7CB092ECF8D1A3AA",
    },

    /* FIPS 198, A.4, SHA-1 with 49-Byte Key, Truncated to 12-Byte HMAC */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key = "707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E"
               "8F909192939495969798999A9B9C9D9E9FA0",
        .msg = "53616D706C65202334",
        .output = "9EA886EFE268DBECCE420C75",
    },

    /*
     * NIST CAVP Test Vectors for Keyed-Hash Message Authentication Code
     * (HMAC), example vector labelled Count=45, Klen=10, Tlen=20. Key size is
     * smaller than block size.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key = "59785928D72516E31272",
        .msg =
            "A3CE8899DF1022E8D2D539B47BF0E309C66F84095E21438EC355BF119CE5FDCB4"
            "E73A619CDF36F25B369D8C38FF419997F0C59830108223606E31223483FD39EDE"
            "AA4D3F0D21198862D239C9FD26074130FF6C86493F5227AB895C8F244BD42C7AF"
            "CE5D147A20A590798C68E708E964902D124DADECDBDA9DBD0051ED710E9BF",
        .output = "3C8162589AAFAEE024FC9A5CA50DD2336FE3EB28",
    },

    /*
     * NIST CAVP Test Vectors for Keyed-Hash Message Authentication Code
     * (HMAC), example vector labelled Count=165, Klen=64, Tlen=20. Key size is
     * equal to block size.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key =
            "B9575F4D5ECC0F4F62E4A0556BB89464BA97D4570E55ACD4C5E5177E452A3D6C9"
            "A0B3ADB60C6211FE48640E08637A6826299E3E52F930F4F66CB0EA6A77311E3",
        .msg =
            "8C8387F4AE2CA1A6DD13D29E93580B1CDF6268DA66CF589CA8B1FF0884F7D8B8F"
            "E299F8E41596E47E0562653612210E4FCA6C446A0A54A6E37EF80D52BD7BB8729"
            "E6B17625D197159EA98622235223C316367FD5B03A3C8145F2F210C910D000942"
            "38757627E63379E75BBB3E0D08CE1B47961309D7876FC59211C60678C5F4C",
        .output = "15AF23331648171499B58042DBE7B2D5DF72D152",
    },

    /*
     * NIST CAVP Test Vectors for Keyed-Hash Message Authentication Code
     * (HMAC), example vector labelled Count=225, Klen=70, Tlen=20. Key size is
     * larger than block size.
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key = "F0DAE6D8753076B1895C01262CA9B57633EB28B3F963A7C752E2CBB4C0314C"
               "20EAB11A10493FAAF4255A8EE4C0884929D1F561FF335EB699DF2D116618E6"
               "0093E5C1E2D1C499",
        .msg =
            "61CB9E1F1E4B3A3B3BDFF8CD5F24566B987F75C8A05377855F772B49B0E7EC136"
            "8B9C6CF9553DB2803DC059E05F0BDD871983C3BED79DFBB694BD0F1ED8DE36E95"
            "77BE50DA313D13124215A93A4BB7CCF4F57793CC28ED43BF7E9B68FEF7D125EFE"
            "ECEC9754B28A271FB6E16899D0BEF287E6DF7C5C867C569F6D4D66B8B7EE0",
        .output = "62AC956ADA19F04BE50C23F2328A32477CD58FB9",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA-1, first sample, with message: "Sample message for
     * keylen=blocklen".
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B"
               "6C656E",
        .output = "5FD596EE78D5553C8FF4E72D266DFD192366DA29",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA-1, second sample, with message: "Sample message for
     * keylen<blocklen".
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key = "000102030405060708090A0B0C0D0E0F10111213",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B"
               "6C656E",
        .output = "4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA-1, third sample, with message: "Sample message for
     * keylen=blocklen" (note: the input message doesn't accurately describe
     * the test, which has a key length larger than the block length of SHA-1).
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"
               "1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D"
               "3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C"
               "5D5E5F60616263",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B"
               "6C656E",
        .output = "2D51B2F7750E410584662E38F133435F4C4FD42A",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA-1, fourth sample, with message: "Sample message for
     * keylen<blocklen, with truncated tag".
     */
    {
        .hashAlg = CHF_ALG_SHA1,
        .key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"
               "1F202122232425262728292A2B2C2D2E2F30",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B"
               "6C656E2C2077697468207472756E636174656420746167",
        .output = "FE3529565CD8E28C5FA79EAC",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA3-512, Sample #1, with message: "Sample message for
     * keylen<blocklen".
     */
    {
        .hashAlg = CHF_ALG_SHA3_512,
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B"
               "6C656E",
        .output =
            "4EFD629D6C71BF86162658F29943B1C308CE27CDFA6DB0D9C3CE81763F9CBCE5F"
            "7EBE9868031DB1A8F8EB7B6B95E5C5E3F657A8996C86A2F6527E307F0213196",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA3-512, Sample #2, with message: "Sample message for
     * keylen=blocklen".
     */
    {
        .hashAlg = CHF_ALG_SHA3_512,
        .key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"
               "1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D"
               "3E3F4041424344454647",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B"
               "6C656E",
        .output =
            "544E257EA2A3E5EA19A590E6A24B724CE6327757723FE2751B75BF007D80F6B36"
            "0744BF1B7A88EA585F9765B47911976D3191CF83C039F5FFAB0D29CC9D9B6DA",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA3-512, Sample #3, with message: "Sample message for
     * keylen>blocklen".
     */
    {
        .hashAlg = CHF_ALG_SHA3_512,
        .key = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E"
               "1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D"
               "3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C"
               "5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B"
               "7C7D7E7F8081828384858687",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3E626C6F636B"
               "6C656E",
        .output =
            "5F464F5E5B7848E3885E49B2C385F0694985D0E38966242DC4A5FE3FEA4B37D46"
            "B65CECED5DCF59438DD840BAB22269F0BA7FEBDB9FCF74602A35666B2A32915",
    },

    /*
     * NIST Cryptographic Standards and Guidelines, Examples with Intermediate
     * Values, SHA3-512, Sample #4, with message: "Sample message for
     * keylen<blocklen, with truncated tag".
     */
    {
        .hashAlg = CHF_ALG_SHA3_512,
        .key =
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2"
            "02122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
        .msg = "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B"
               "6C656E2C2077697468207472756E636174656420746167",
        .output =
            "7BB06D859257B25CE73CA700DF34C5CBEF5C898BAC91029E0B27975D4E526A08",
    },
};

/*
 * Run the HMAC tests and report the success rate.
 */
int main()
{
    size_t onTest;

    for (onTest = 0; onTest < sizeof(allTests) / sizeof(struct hmac_test);
         onTest++) {
        run_hmac_test(&allTests[onTest]);
    }

    TEST_CONCLUDE();
}

static void run_hmac_test(const struct hmac_test *test)
{
    byte_t *key, *msg, *output;
    size_t keyLen, msgLen, outputLen;

    hex_to_bytes(test->key, &key, &keyLen);
    hex_to_bytes(test->msg, &msg, &msgLen);
    hex_to_bytes(test->output, &output, &outputLen);

    run_parsed_hmac_test(test->hashAlg, key, keyLen, msg, msgLen, output,
                         outputLen);

    free(key);
    free(msg);
    free(output);
}

static void run_parsed_hmac_test(chf_algorithm_t hashAlg, const byte_t *key,
                                 size_t keyLen, const byte_t *msg,
                                 size_t msgLen, const byte_t *output,
                                 size_t outputLen)
{
    struct hmac_ctx *ctx;
    byte_t actual[HMAC_MAX_DIGEST_BYTES];

    ctx = hmac_alloc(hashAlg);
    ASSERT(outputLen <= hmac_digest_size(ctx),
           "HMAC test output larger than digest size");

    memset(actual, 0, outputLen);
    hmac_single(ctx, key, keyLen, msg, msgLen, actual);
    TEST_ASSERT(memcmp(actual, output, outputLen) == 0);

    hmac_free_scrub(ctx);
}
