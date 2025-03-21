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
#include "crypto/primitives/sha3/sha3.h"
#include "crypto/test/framework.h"
#include "crypto/test/hex.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

TEST_PREAMBLE("SHA3");

/*
 * Parameters for testing the output of a single invocation of the SHA-3
 * algorithm, where the input is a single message.
 */
struct sha3_plain_test {
    const char *msg;
    const char *digest;
};

/*
 * Parameters for a SHA-3 test using the NIST Secure Hash Algorithm 3
 * Validation System (SHA3VS) Monte Carlo Test (MCT) algorithm.
 */
struct sha3_monte_test {
    const char *seed;
    const char *output;
};

/*
 * Runs a SHA-3 single-output test, and asserts that the output matches the
 * expected digest in the given test parameters.
 */
static void run_sha3_plain_test(const struct sha3_plain_test *test);

/*
 * Runs a SHA-3 single-output test which has been parsed from its hexadecimal
 * string format.
 */
static void run_parsed_sha3_plain_test(const byte_t *msg, size_t msgLen,
                                       const byte_t *digest, size_t digestLen);

/*
 * Adds the provided message to the currently running SHA-3 context. If the
 * message is larger than one block in size, it will be broken up and added in
 * three pieces (to test the functionality of adding partial blocks to the
 * context).
 */
static void add_single_message(struct sha3_ctx *ctx, const byte_t *msg,
                               size_t msgLen, size_t digestLen);

/*
 * Runs a single SHA-3 NIST SHA3VS MCT case, which includes a single assertion:
 * that the outcome of the loop of hash invocations is correct.
 */
static void run_sha3_monte_test(const struct sha3_monte_test *test);

/*
 * Runs a single SHA-3 NIST SHA3VS MCT case, which has been parsed from its
 * hexadecimal string format. The value of digestLen must be the number of
 * bytes in both the seed and the output.
 */
static void run_parsed_sha3_monte_test(const byte_t *seed,
                                       const byte_t *output, size_t digestLen);

/*
 * Converts strings of hexadecimal characters to arrays of bytes, and ensures
 * that the number of digest bytes converted is a valid SHA-3 digest size. The
 * caller is responsible for freeing the allocated byte arrays.
 */
static void parse_hex_to_bytes(const char *msgHex, byte_t **msgBytes,
                               size_t *msgLen, const char *digestHex,
                               byte_t **digestBytes, size_t *digestLen);

/*
 * Starts the SHA-3 context running an operation that outputs the given number
 * of bytes as a digest.
 */
static void start_ctx(struct sha3_ctx *ctx, size_t digestLen);

/*
 * Returns the number of bytes in a block, when SHA-3 is running with the given
 * number of bytes as a digest output size.
 */
static size_t block_bytes(size_t digestLen);

/*
 * All of the single-output SHA-3 tests to run.
 */
static const struct sha3_plain_test plainTests[] = {
    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-224 ShortMsg, Len=0 (0 bytes).
     */
    {
        .msg = "",
        .digest = "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-256 ShortMsg, Len=0 (0 bytes).
     */
    {
        .msg = "",
        .digest =
            "A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-384 ShortMsg, Len=0 (0 bytes).
     */
    {
        .msg = "",
        .digest = "0C63A75B845E4F7D01107D852E4C2485C51A50AAAA94FC61995E71BBEE9"
                  "83A2AC3713831264ADB47FB6BD1E058D5F004",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-512 ShortMsg, Len=0 (0 bytes).
     */
    {
        .msg = "",
        .digest =
            "A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A61"
            "5B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-224 ShortMsg, Len=24 (3 bytes).
     * Less-than-one-block input message.
     */
    {
        .msg = "BF5831",
        .digest = "1BB36BEBDE5F3CB6D8E4672ACF6EEC8728F31A54DACC2560DA2A00CC",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-256 ShortMsg, Len=24 (3 bytes).
     * Less-than-one-block input message.
     */
    {
        .msg = "B053FA",
        .digest =
            "9D0FF086CD0EC06A682C51C094DC73ABDC492004292344BD41B82A60498CCFDB",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-384 ShortMsg, Len=24 (3 bytes).
     * Less-than-one-block input message.
     */
    {
        .msg = "6AB7D6",
        .digest = "EA12D6D32D69AD2154A57E0E1BE481A45ADD739EE7DD6E2A27E544B6C8B"
                  "5AD122654BBF95134D567987156295D5E57DB",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-512 ShortMsg, Len=24 (3 bytes).
     * Less-than-one-block input message.
     */
    {
        .msg = "37D518",
        .digest =
            "4AA96B1547E6402C0EEE781ACAA660797EFE26EC00B4F2E0AEC4A6D10688DD64C"
            "BD7F12B3B6C7F802E2096C041208B9289AEC380D1A748FDFCD4128553D781E3",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-224 ShortMsg, Len=1152 (144
     * bytes). Exactly-one-block input message.
     */
    {
        .msg = "E65DE91FDCB7606F14DBCFC94C9C94A57240A6B2C31ED410346C4DC0115265"
               "59E44296FC988CC589DE2DC713D0E82492D4991BD8C4C5E6C74C753FC09345"
               "225E1DB8D565F0CE26F5F5D9F404A28CF00BD655A5FE04EDB682942D675B86"
               "235F235965AD422BA5081A21865B8209AE81763E1C4C0CCCBCCDAAD539CF77"
               "3413A50F5FF1267B9238F5602ADC06764F775D3C",
        .digest = "26EC9DF54D9AFE11710772BFBECCC83D9D0439D3530777C81B8AE6A3",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-256 ShortMsg, Len=1088 (136
     * bytes). Exactly-one-block input message.
     */
    {
        .msg = "56EA14D7FCB0DB748FF649AAA5D0AFDC2357528A9AAD6076D73B2805B53D89"
               "E73681ABFAD26BEE6C0F3D20215295F354F538AE80990D2281BE6DE0F6919A"
               "A9EB048C26B524F4D91CA87B54C0C54AA9B54AD02171E8BF31E8D158A9F586"
               "E92FFCE994ECCE9A5185CC80364D50A6F7B94849A914242FCB73F33A86ECC8"
               "3C3403630D20650DDB8CD9C4",
        .digest =
            "4BEAE3515BA35EC8CBD1D94567E22B0D7809C466ABFBAFE9610349597BA15B45",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-384 ShortMsg, Len=832 (104
     * bytes). Exactly-one-block input message.
     */
    {
        .msg = "92C41D34BD249C182AD4E18E3B856770766F1757209675020D4C1CF7B6F768"
               "6C8C1472678C7C412514E63EB9F5AEE9F5C9D5CB8D8748AB7A5465059D9CBB"
               "B8A56211FF32D4AAA23A23C86EAD916FE254CC6B2BFF7A9553DF1551B531F9"
               "5BB41CBBC4ACDDBD372921",
        .digest = "71307EEC1355F73E5B726ED9EFA1129086AF81364E30A291F684DFADE69"
                  "3CC4BC3D6FFCB7F3B4012A21976FF9EDCAB61",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-512 ShortMsg, Len=576 (72 bytes).
     * Exactly-one-block input message.
     */
    {
        .msg = "0CE9F8C3A990C268F34EFD9BEFDB0F7C4EF8466CFDB01171F8DE70DC5FEFA9"
               "2ACBE93D29E2AC1A5C2979129F1AB08C0E77DE7924DDF68A209CDFA0ADC62F"
               "85C18637D9C6B33F4FF8",
        .digest =
            "B018A20FCF831DDE290E4FB18C56342EFE138472CBE142DA6B77EEA4FCE52588C"
            "04C808EB32912FAA345245A850346FAEC46C3A16D39BD2E1DDB1816BC57D2DA",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-224 LongMsg, Len=2312 (289
     * bytes). Larger-than-one-block input message.
     */
    {
        .msg =
            "31C82D71785B7CA6B651CB6C8C9AD5E2ACEB0B0633C088D33AA247ADA7A594FF4"
            "936C023251319820A9B19FC6C48DE8A6F7ADA214176CCDAADAEEF51ED43714AC0"
            "C8269BBD497E46E78BB5E58196494B2471B1680E2D4C6DBD249831BD83A4D3BE0"
            "6C8A2E903933974AA05EE748BFE6EF359F7A143EDF0D4918DA916BD6F15E26A79"
            "0CFF514B40A5DA7F72E1ED2FE63A05B8149587BEA05653718CC8980EADBFECA85"
            "B7C9C286DD040936585938BE7F98219700C83A9443C2856A80FF46852B26D1B1E"
            "DF72A30203CF6C44A10FA6EAF1920173CEDFB5C4CF3AC665B37A86ED02155BBBF"
            "17DC2E786AF9478FE0889D86C5BFA85A242EB0854B1482B7BD16F67F80BEF9C7A"
            "628F05A107936A64273A97B0088B0E515451F916B5656230A12BA6DC78",
        .digest = "AAB23C9E7FB9D7DACEFDFD0B1AE85AB1374ABFF7C4E3F7556ECAE412",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-256 LongMsg, Len=2184 (273
     * bytes). Larger-than-one-block input message.
     */
    {
        .msg = "B1CAA396771A09A1DB9BC20543E988E359D47C2A616417BBCA1B62CB02796A"
               "888FC6EEFF5C0B5C3D5062FCB4256F6AE1782F492C1CF03610B4A1FB7B814C"
               "057878E1190B9835425C7A4A0E182AD1F91535ED2A35033A5D8C670E21C575"
               "FF43C194A58A82D4A1A44881DD61F9F8161FC6B998860CBE4975780BE93B6F"
               "87980BAD0A99AA2CB7556B478CA35D1F3746C33E2BB7C47AF426641CC7BBB3"
               "425E2144820345E1D0EA5B7DA2C3236A52906ACDC3B4D34E474DD714C0C40B"
               "F006A3A1D889A632983814BBC4A14FE5F159AA89249E7C738B3B73666BAC2A"
               "615A83FD21AE0A1CE7352ADE7B278B587158FD2FABB217AA1FE31D0BDA5327"
               "2045598015A8AE4D8CEC226FEFA58DAA05500906C4D85E7567",
        .digest =
            "CB5648A1D61C6C5BDACD96F81C9591DEBC3950DCF658145B8D996570BA881A05",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-384 LongMsg, Len=1672 (209
     * bytes). Larger-than-one-block input message.
     */
    {
        .msg = "5FE35923B4E0AF7DD24971812A58425519850A506DFA9B0D254795BE785786"
               "C319A2567CBAA5E35BCF8FE83D943E23FA5169B73ADC1FCF8B607084B15E6A"
               "013DF147E46256E4E803AB75C110F77848136BE7D806E8B2F868C16C3A90C1"
               "4463407038CB7D9285079EF162C6A45CEDF9C9F066375C969B5FCBCDA37F02"
               "AACFF4F31CDED3767570885426BEBD9ECA877E44674E9AE2F0C24CDD0E7E1A"
               "AF1FF2FE7F80A1C4F5078EB34CD4F06FA94A2D1EAB5806CA43FD0F06C60B63"
               "D5402B95C70C21EA65A151C5CFAF8262A46BE3C722264B",
        .digest = "3054D249F916A6039B2A9C3EBEC1418791A0608A170E6D36486035E5F92"
                  "635EABA98072A85373CB54E2AE3F982CE132B",
    },

    /*
     * NIST CAVP SHA-3 Hash Function Test Vectors for Hashing Byte-Oriented
     * Messages, example vector labelled SHA3-512 LongMsg, Len=1160 (145
     * bytes). Larger-than-one-block input message.
     */
    {
        .msg = "664EF2E3A7059DAF1C58CAF52008C5227E85CDCB83B4C59457F02C508D4F4F"
               "69F826BD82C0CFFC5CB6A97AF6E561C6F96970005285E58F21EF6511D26E70"
               "9889A7E513C434C90A3CF7448F0CAEEC7114C747B2A0758A3B4503A7CF0C69"
               "873ED31D94DBEF2B7B2F168830EF7DA3322C3D3E10CAFB7C2C33C83BBF4C46"
               "A31DA90CFF3BFD4CCC6ED4B310758491EEBA603A76",
        .digest =
            "E5825FF1A3C070D5A52FBBE711854A440554295FFB7A7969A17908D10163BFBE8"
            "F1D52A676E8A0137B56A11CDF0FFBB456BC899FC727D14BD8882232549D914E",
    },
};

/*
 * All of the SHA-3 NIST SHA3VS MCT tests to run.
 */
static const struct sha3_monte_test monteTests[] = {
    /*
     * NIST CAVP MCT Vectors for SHA-3, example vector labelled SHA3-224 Monte,
     * L=224, with the Seed as input and COUNT=99 as output.
     */
    {
        .seed = "3A9415D401AEB8567E6F0ECEE311F4F716B39E86045C8A51383DB2B6",
        .output = "91DEFBE230B514D7DB13D915A82368D32D48F55DB31D16E3AE7FBBD0",
    },

    /*
     * NIST CAVP MCT Vectors for SHA-3, example vector labelled SHA3-256 Monte,
     * L=256, with the Seed as input and COUNT=99 as output.
     */
    {
        .seed =
            "AA64F7245E2177C654EB4DE360DA8761A516FDC7578C3498C5E582E096B8730C",
        .output =
            "456F2ED7F5433BB4E56D7780A21A953E95D6A5EB53BB4C974C57A90E677F3197",
    },

    /*
     * NIST CAVP MCT Vectors for SHA-3, example vector labelled SHA3-384 Monte,
     * L=384, with the Seed as input and COUNT=99 as output.
     */
    {
        .seed = "7A00791F6F65C21F1C97C58FA3C0520CFC85CD7E3D398CF01950819FA7171"
                "95065A363E77D07753647CB0C130E9972AD",
        .output = "02C9BABD4ADD11A5F23C1808F72E3DC8325CEDC31D28213A04D999DAC8F"
                  "46B866F84BA3DBFBCF1A863CC54D808FFADCA",
    },

    /*
     * NIST CAVP MCT Vectors for SHA-3, example vector labelled SHA3-512 Monte,
     * L=512, with the Seed as input and COUNT=99 as output.
     */
    {
        .seed =
            "764A5511F00DBB0EAEF2EB27AD58D35F74F563B88F789FF53F6CF3A47060C75CE"
            "B455444CD17B6D438C042E0483919D249F2FD372774647D2545CBFAD20B4D31",
        .output =
            "760824A439B0681FCD5D22F8467D927A764FEBC457FD1EB62584CA82B00E1A079"
            "05A0117A955041892D2C9D849C096067ED2893ACA5C841F8AA32DABE642BC82",
    },
};

/*
 * Run the SHA-3 tests and report the success rate.
 */
int main(void)
{
    size_t onTest;

    for (onTest = 0;
         onTest < sizeof(plainTests) / sizeof(struct sha3_plain_test);
         onTest++) {
        run_sha3_plain_test(&plainTests[onTest]);
    }

    for (onTest = 0;
         onTest < sizeof(monteTests) / sizeof(struct sha3_monte_test);
         onTest++) {
        run_sha3_monte_test(&monteTests[onTest]);
    }

    TEST_CONCLUDE();
}

static void run_sha3_plain_test(const struct sha3_plain_test *test)
{
    byte_t *msg, *digest;
    size_t msgLen, digestLen;

    parse_hex_to_bytes(test->msg, &msg, &msgLen, test->digest, &digest,
                       &digestLen);
    run_parsed_sha3_plain_test(msg, msgLen, digest, digestLen);

    free(msg);
    free(digest);
}

static void run_parsed_sha3_plain_test(const byte_t *msg, size_t msgLen,
                                       const byte_t *digest, size_t digestLen)
{
    struct sha3_ctx *ctx;
    byte_t actual[SHA3_DIGEST_BYTES_MAX];

    ctx = sha3_alloc();
    memset(actual, 0, digestLen);

    start_ctx(ctx, digestLen);
    add_single_message(ctx, msg, msgLen, digestLen);
    sha3_end(ctx, actual);

    TEST_ASSERT(memcmp(actual, digest, digestLen) == 0);
    sha3_free_scrub(ctx);
}

static void add_single_message(struct sha3_ctx *ctx, const byte_t *msg,
                               size_t msgLen, size_t digestLen)
{
    size_t blockBytes = block_bytes(digestLen);
    size_t quarterBlockBytes = blockBytes / 4;

    if (msgLen <= blockBytes) {
        sha3_add(ctx, msg, msgLen);
    }
    else {
        /* Test the functionality of breaking larger messages into parts */
        sha3_add(ctx, msg, quarterBlockBytes);
        sha3_add(ctx, msg + quarterBlockBytes, msgLen - 2 * quarterBlockBytes);
        sha3_add(ctx, msg + msgLen - quarterBlockBytes, quarterBlockBytes);
    }
}

static void run_sha3_monte_test(const struct sha3_monte_test *test)
{
    byte_t *seed, *output;
    size_t seedLen, digestLen;

    parse_hex_to_bytes(test->seed, &seed, &seedLen, test->output, &output,
                       &digestLen);
    ASSERT(seedLen == digestLen,
           "MCT seed length does not match digest length");

    run_parsed_sha3_monte_test(seed, output, digestLen);

    free(seed);
    free(output);
}

static void run_parsed_sha3_monte_test(const byte_t *seed,
                                       const byte_t *output, size_t digestLen)
{
    const int NIST_MONTE_COMBINED_LOOP_SIZE = 100000;
    struct sha3_ctx *ctx;
    const byte_t *input;
    byte_t actual[SHA3_DIGEST_BYTES_MAX];
    int k;

    ctx = sha3_alloc();
    memset(actual, 0, digestLen);

    /*
     * The SHA-3 NIST SHA3VS Monte Carlo Test algorithm is described on page 13
     * of the SHA3VS document. The algorithm, with its two loops merged for
     * greater clarity, uses the variable:
     *
     * md[k]  where 0 <= k < 100000
     *
     * where:
     *
     * md[0] = the provided input seed
     */
    input = seed;
    for (k = 0; k < NIST_MONTE_COMBINED_LOOP_SIZE; k++) {
        start_ctx(ctx, digestLen);
        sha3_add(ctx, input, digestLen);
        sha3_end(ctx, actual);
        input = actual;
    }

    /*
     * md[99999] is the expected output of the SHA-3 MCT.
     *
     * Note: in the SHA3VS CAVP, each md[100 * j + 999] is output as an
     * intermediate computation, for 0 <= j < 100. Here, we check only the
     * final result.
     */
    TEST_ASSERT(memcmp(actual, output, digestLen) == 0);
    sha3_free_scrub(ctx);
}

static void parse_hex_to_bytes(const char *msgHex, byte_t **msgBytes,
                               size_t *msgLen, const char *digestHex,
                               byte_t **digestBytes, size_t *digestLen)
{
    hex_to_bytes(msgHex, msgBytes, msgLen);
    hex_to_bytes(digestHex, digestBytes, digestLen);

    ASSERT(*digestLen == SHA3_224_DIGEST_BYTES ||
               *digestLen == SHA3_256_DIGEST_BYTES ||
               *digestLen == SHA3_384_DIGEST_BYTES ||
               *digestLen == SHA3_512_DIGEST_BYTES,
           "Invalid SHA-3 digest length");
}

static void start_ctx(struct sha3_ctx *ctx, size_t digestLen)
{
    switch (digestLen) {
    case SHA3_224_DIGEST_BYTES:
        sha3_224_start(ctx);
        break;
    case SHA3_256_DIGEST_BYTES:
        sha3_256_start(ctx);
        break;
    case SHA3_384_DIGEST_BYTES:
        sha3_384_start(ctx);
        break;
    case SHA3_512_DIGEST_BYTES:
        sha3_512_start(ctx);
        break;
    default:
        FATAL_ERROR("Invalid SHA-3 digest size");
    }
}

static size_t block_bytes(size_t digestLen)
{
    switch (digestLen) {
    case SHA3_224_DIGEST_BYTES:
        return SHA3_224_BLOCK_BYTES;
    case SHA3_256_DIGEST_BYTES:
        return SHA3_256_BLOCK_BYTES;
    case SHA3_384_DIGEST_BYTES:
        return SHA3_384_BLOCK_BYTES;
    case SHA3_512_DIGEST_BYTES:
        return SHA3_512_BLOCK_BYTES;
    default:
        FATAL_ERROR("Invalid SHA-3 digest size");
    }
}
