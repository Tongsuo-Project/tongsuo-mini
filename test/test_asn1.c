/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include "test.h"

int test_asn1_encode_bool(void)
{
    unsigned char out[3];
    size_t outl;
    unsigned char *p;

    // False, 0x01 01 00
    p = out, outl = 0;
    ASSERT_OK(asn1_encode_bool(&p, &outl, 0));
    ASSERT(out[0] == TONGSUO_ASN1_BOOLEAN && out[1] == 1 && out[2] == 0);
    ASSERT(outl == 3 && (size_t)(p - out) == outl);

    // True, 0x01 01 FF
    p = out, outl = 0;
    ASSERT_OK(asn1_encode_bool(&p, &outl, 1));
    ASSERT(out[0] == TONGSUO_ASN1_BOOLEAN && out[1] == 1 && out[2] == 0xFF);
    ASSERT(outl == 3 && (size_t)(p - out) == outl);

    // True, 2, 0x01 01 FF
    p = out, outl = 0;
    ASSERT_OK(asn1_encode_bool(&p, &outl, 2));
    ASSERT(out[0] == TONGSUO_ASN1_BOOLEAN && out[1] == 1 && out[2] == 0xFF);
    ASSERT(outl == 3 && (size_t)(p - out) == outl);
    return 0;
}

int test_asn1_decode_bool(void)
{
    unsigned char *p;
    unsigned char in[3];
    int val;

    // False, 0
    in[0] = TONGSUO_ASN1_BOOLEAN, in[1] = 1, in[2] = 0;
    p = in;
    ASSERT_OK(asn1_decode_bool(&p, sizeof(in), &val));
    ASSERT(val == 0 && (size_t)(p - in) == sizeof(in));

    // True, 0xFF
    in[0] = TONGSUO_ASN1_BOOLEAN, in[1] = 1, in[2] = 0xFF;
    p = in;
    ASSERT_OK(asn1_decode_bool(&p, sizeof(in), &val));
    ASSERT(val == 1 && (size_t)(p - in) == sizeof(in));

    // False, neithor 0 nor 0xFF
    in[0] = TONGSUO_ASN1_BOOLEAN, in[1] = 1, in[2] = 1;
    p = in;
    ASSERT_OK(asn1_decode_bool(&p, sizeof(in), &val));
    ASSERT(val == 0 && (size_t)(p - in) == sizeof(in));

    // Bad asn1 len
    in[0] = TONGSUO_ASN1_BOOLEAN, in[1] = 2;
    p = in;
    ASSERT_ERR(asn1_decode_bool(&p, sizeof(in), &val));

    // Small inlen
    in[0] = TONGSUO_ASN1_BOOLEAN, in[1] = 1;
    p = in;
    ASSERT_ERR(asn1_decode_bool(&p, 2, &val));

    return 0;
}

int test_asn1_encode_int(void)
{
    unsigned char out[1024];
    size_t outl;
    unsigned char *p;

    // 0, 0x02 01 00
    p = out;
    outl = 0;
    ASSERT_OK(asn1_encode_int(&p, &outl, 0));
    ASSERT(out[0] == TONGSUO_ASN1_INTEGER && out[1] == 1 && out[2] == 0);
    ASSERT(outl == 3 && (size_t)(p - out) == outl);

    // 1, 0x02 01 01
    p = out;
    outl = 0;
    ASSERT_OK(asn1_encode_int(&p, &outl, 1));
    ASSERT(out[0] == TONGSUO_ASN1_INTEGER && out[1] == 1 && out[2] == 1);
    ASSERT(outl == 3 && (size_t)(p - out) == outl);

    // 127, 0x02 01 7F
    p = out;
    outl = 0;
    ASSERT_OK(asn1_encode_int(&p, &outl, 127));
    ASSERT(out[0] == TONGSUO_ASN1_INTEGER && out[1] == 1 && out[2] == 127);
    ASSERT(outl == 3 && (size_t)(p - out) == outl);

    // 128, 0x02 02 00 80
    p = out;
    outl = 0;
    ASSERT_OK(asn1_encode_int(&p, &outl, 128));
    ASSERT(out[0] == TONGSUO_ASN1_INTEGER && out[1] == 2 && out[2] == 0 && out[3] == 128);
    ASSERT(outl == 4 && (size_t)(p - out) == outl);

    // 1234567890, 0x02 04 49 96 02 D2
    p = out;
    outl = 0;
    ASSERT_OK(asn1_encode_int(&p, &outl, 1234567890));
    ASSERT(out[0] == TONGSUO_ASN1_INTEGER && out[1] == 4 && out[2] == 0x49 && out[3] == 0x96
           && out[4] == 0x02 && out[5] == 0xD2);
    ASSERT(outl == 6 && (size_t)(p - out) == outl);

    // -1, negative is not supported
    p = out;
    outl = 0;
    ASSERT_ERR(asn1_encode_int(&p, &outl, -1));

    return 0;
}

int test_asn1_decode_int(void)
{
    unsigned char *p;
    unsigned char in[1024];
    int val;

    // 0, 0x02 01 00
    in[0] = TONGSUO_ASN1_INTEGER, in[1] = 1, in[2] = 0;
    p = in;
    ASSERT_OK(asn1_decode_int(&p, sizeof(in), &val));
    ASSERT(val == 0 && (size_t)(p - in) == 3);

    // 1, 0x02 01 01
    in[0] = TONGSUO_ASN1_INTEGER, in[1] = 1, in[2] = 1;
    p = in;
    ASSERT_OK(asn1_decode_int(&p, sizeof(in), &val));
    ASSERT(val == 1 && (size_t)(p - in) == 3);

    // 127, 0x02 01 7F
    in[0] = TONGSUO_ASN1_INTEGER, in[1] = 1, in[2] = 127;
    p = in;
    ASSERT_OK(asn1_decode_int(&p, sizeof(in), &val));
    ASSERT(val == 127 && (size_t)(p - in) == 3);

    // 128, 0x02 02 00 80
    in[0] = TONGSUO_ASN1_INTEGER, in[1] = 2, in[2] = 0, in[3] = 128;
    p = in;
    ASSERT_OK(asn1_decode_int(&p, sizeof(in), &val));
    ASSERT(val == 128 && (size_t)(p - in) == 4);

    // 1234567890, 0x02 04 49 96 02 D2
    in[0] = TONGSUO_ASN1_INTEGER, in[1] = 4, in[2] = 0x49, in[3] = 0x96, in[4] = 0x02, in[5] = 0xD2;
    p = in;
    ASSERT_OK(asn1_decode_int(&p, sizeof(in), &val));
    ASSERT(val == 1234567890 && (size_t)(p - in) == 6);

    // -1, negative is not supported
    in[0] = TONGSUO_ASN1_INTEGER, in[1] = 1, in[2] = 0xFF;
    p = in;
    ASSERT_ERR(asn1_decode_int(&p, sizeof(in), &val));

    return 0;
}

int test_asn1_encode_bit_string(void)
{
    unsigned char out[128];
    size_t outl;
    unsigned char *p;
    const unsigned char *bs;

    // empty bitstring, 0x03 01 00
    p = out, outl = 0;
    ASSERT_OK(asn1_encode_bit_string(&p, &outl, NULL, 0));
    ASSERT(out[0] == TONGSUO_ASN1_BIT_STRING && out[1] == 1 && out[2] == 0);
    ASSERT(outl == 3 && (size_t)(p - out) == outl);

    // 1001, 0x03 02 04 90
    bs = (const unsigned char *)"\x90", p = out, outl = 0;
    ASSERT_OK(asn1_encode_bit_string(&p, &outl, bs, 4));
    ASSERT(out[0] == TONGSUO_ASN1_BIT_STRING && out[1] == 2 && out[2] == 4 && out[3] == 0x90);
    ASSERT(outl == 4 && (size_t)(p - out) == outl);

    // 10001110, 0x03 02 00 8E
    bs = (const unsigned char *)"\x8E", p = out, outl = 0;
    ASSERT_OK(asn1_encode_bit_string(&p, &outl, bs, 8));
    ASSERT(out[0] == TONGSUO_ASN1_BIT_STRING && out[1] == 2 && out[2] == 0 && out[3] == 0x8E);
    ASSERT(outl == 4 && (size_t)(p - out) == outl);

    return 0;
}

int test_asn1_decode_bit_string(void)
{
    unsigned char *p;
    unsigned char in[128];
    unsigned char bs[128];
    size_t nbits;

    // empty bitstring, 0x03 01 00
    in[0] = TONGSUO_ASN1_BIT_STRING, in[1] = 1, in[2] = 0;
    p = in;
    ASSERT_OK(asn1_decode_bit_string(&p, sizeof(in), bs, &nbits));
    ASSERT(nbits == 0 && (size_t)(p - in) == 3);

    // 1001, 0x03 02 04 90
    in[0] = TONGSUO_ASN1_BIT_STRING, in[1] = 2, in[2] = 4, in[3] = 0x90;
    p = in;
    ASSERT_OK(asn1_decode_bit_string(&p, sizeof(in), bs, &nbits));
    ASSERT(nbits == 4 && (size_t)(p - in) == 4);

    // 10001110, 0x03 02 00 8E
    in[0] = TONGSUO_ASN1_BIT_STRING, in[1] = 2, in[2] = 0, in[3] = 0x8E;
    p = in;
    ASSERT_OK(asn1_decode_bit_string(&p, sizeof(in), bs, &nbits));
    ASSERT(nbits == 8 && (size_t)(p - in) == 4);

    return 0;
}

int test_asn1_encode_octet_string(void)
{
    unsigned char *p;
    unsigned char out[128];
    size_t outl;

    // empty octet string, 0x04 00
    p = out, outl = 0;
    ASSERT_OK(asn1_encode_octet_string(&p, &outl, NULL, 0));
    ASSERT(out[0] == TONGSUO_ASN1_OCTET_STRING && out[1] == 0);

    // 0x01 02 03 04, 0x04 04 01 02 03 04
    p = out, outl = 0;
    ASSERT_OK(asn1_encode_octet_string(&p, &outl, (const unsigned char *)"\x01\x02\x03\x04", 4));
    ASSERT(out[0] == TONGSUO_ASN1_OCTET_STRING && out[1] == 4 && out[2] == 0x01 && out[3] == 0x02
           && out[4] == 0x03 && out[5] == 0x04);

    return 0;
}

int test_asn1_encode_null(void)
{
    unsigned char *p;
    unsigned char out[128];
    size_t outl;

    // null, 0x05 00
    p = out, outl = 0;
    ASSERT_OK(asn1_encode_null(&p, &outl));
    ASSERT(out[0] == TONGSUO_ASN1_NULL && out[1] == 0);
    ASSERT(outl == 2 && (size_t)(p - out) == outl);

    return 0;
}

int test_asn1_decode_null(void)
{
    unsigned char *p;
    unsigned char in[2];

    // null, 0x05 00
    p = in, in[0] = TONGSUO_ASN1_NULL, in[1] = 0;
    ASSERT_OK(asn1_decode_null(&p, sizeof(in)));
    ASSERT(p - in == 2);

    return 0;
}

int test_asn1_encode_oid(void)
{
    unsigned char *p;
    unsigned char out[128];
    size_t outl;

    // 1.2.3, 0x06 02 2A 03
    p = out, outl = 0;
    ASSERT_OK(asn1_encode_oid(&p, &outl, (const unsigned char *)"\x2A\x03", 2));
    ASSERT(out[0] == TONGSUO_ASN1_OBJECT_IDENTIFIER && out[1] == 2 && out[2] == 0x2A
           && out[3] == 0x03);
    ASSERT(outl == 4 && (size_t)(p - out) == outl);

    return 0;
}

int test_asn1_encode_enum(void)
{
    unsigned char out[1024];
    size_t outl;
    unsigned char *p;

    // 0, 0x02 01 00
    p = out;
    outl = 0;
    ASSERT_OK(asn1_encode_enum(&p, &outl, 0));
    ASSERT(out[0] == TONGSUO_ASN1_ENUMERATED && out[1] == 1 && out[2] == 0);
    ASSERT(outl == 3 && (size_t)(p - out) == outl);

    // 1, 0x02 01 01
    p = out;
    outl = 0;
    ASSERT_OK(asn1_encode_enum(&p, &outl, 1));
    ASSERT(out[0] == TONGSUO_ASN1_ENUMERATED && out[1] == 1 && out[2] == 1);
    ASSERT(outl == 3 && (size_t)(p - out) == outl);

    // 127, 0x02 01 7F
    p = out;
    outl = 0;
    ASSERT_OK(asn1_encode_enum(&p, &outl, 127));
    ASSERT(out[0] == TONGSUO_ASN1_ENUMERATED && out[1] == 1 && out[2] == 127);
    ASSERT(outl == 3 && (size_t)(p - out) == outl);

    // 128, 0x02 02 00 80
    p = out;
    outl = 0;
    ASSERT_OK(asn1_encode_enum(&p, &outl, 128));
    ASSERT(out[0] == TONGSUO_ASN1_ENUMERATED && out[1] == 2 && out[2] == 0 && out[3] == 128);
    ASSERT(outl == 4 && (size_t)(p - out) == outl);

    // 1234567890, 0x02 04 49 96 02 D2
    p = out;
    outl = 0;
    ASSERT_OK(asn1_encode_enum(&p, &outl, 1234567890));
    ASSERT(out[0] == TONGSUO_ASN1_ENUMERATED && out[1] == 4 && out[2] == 0x49 && out[3] == 0x96
           && out[4] == 0x02 && out[5] == 0xD2);
    ASSERT(outl == 6 && (size_t)(p - out) == outl);

    // -1, negative is not supported
    p = out;
    outl = 0;
    ASSERT_ERR(asn1_encode_enum(&p, &outl, -1));

    return 0;
}

int test_asn1_decode_enum(void)
{
    unsigned char *p;
    unsigned char in[1024];
    int val;

    // 0, 0x02 01 00
    in[0] = TONGSUO_ASN1_ENUMERATED, in[1] = 1, in[2] = 0;
    p = in;
    ASSERT_OK(asn1_decode_enum(&p, sizeof(in), &val));
    ASSERT(val == 0 && (size_t)(p - in) == 3);

    // 1, 0x02 01 01
    in[0] = TONGSUO_ASN1_ENUMERATED, in[1] = 1, in[2] = 1;
    p = in;
    ASSERT_OK(asn1_decode_enum(&p, sizeof(in), &val));
    ASSERT(val == 1 && (size_t)(p - in) == 3);

    // 127, 0x02 01 7F
    in[0] = TONGSUO_ASN1_ENUMERATED, in[1] = 1, in[2] = 127;
    p = in;
    ASSERT_OK(asn1_decode_enum(&p, sizeof(in), &val));
    ASSERT(val == 127 && (size_t)(p - in) == 3);

    // 128, 0x02 02 00 80
    in[0] = TONGSUO_ASN1_ENUMERATED, in[1] = 2, in[2] = 0, in[3] = 128;
    p = in;
    ASSERT_OK(asn1_decode_enum(&p, sizeof(in), &val));
    ASSERT(val == 128 && (size_t)(p - in) == 4);

    // 1234567890, 0x02 04 49 96 02 D2
    in[0] = TONGSUO_ASN1_ENUMERATED, in[1] = 4, in[2] = 0x49, in[3] = 0x96, in[4] = 0x02,
    in[5] = 0xD2;
    p = in;
    ASSERT_OK(asn1_decode_enum(&p, sizeof(in), &val));
    ASSERT(val == 1234567890 && (size_t)(p - in) == 6);

    // -1, negative is not supported
    in[0] = TONGSUO_ASN1_ENUMERATED, in[1] = 1, in[2] = 0xFF;
    p = in;
    ASSERT_ERR(asn1_decode_enum(&p, sizeof(in), &val));

    return 0;
}

int test_asn1_encode_printable_string(void)
{
    unsigned char *p;
    unsigned char out[128];
    size_t outl;

    // abc, 0x13 03 61 62 63
    p = out, outl = 0;
    ASSERT_OK(asn1_encode_printable_string(&p, &outl, (unsigned char *)"abc", 3));
    ASSERT(out[0] == TONGSUO_ASN1_PRINTABLE_STRING && out[1] == 3 && out[2] == 'a' && out[3] == 'b'
           && out[4] == 'c');
    ASSERT(outl == 5 && (size_t)(p - out) == outl);

    return 0;
}

int test_asn1_encode_ia5_string(void)
{
    unsigned char *p;
    unsigned char out[128];
    size_t outl;

    // \t\r\n, 0x06 03 09 0D 0A
    p = out, outl = 0;
    ASSERT_OK(asn1_encode_ia5_string(&p, &outl, (unsigned char *)"\t\r\n", 3));
    ASSERT(out[0] == TONGSUO_ASN1_IA5_STRING && out[1] == 3 && out[2] == '\t' && out[3] == '\r'
           && out[4] == '\n');
    ASSERT(outl == 5 && (size_t)(p - out) == outl);

    return 0;
}

int main(void)
{
    TEST(test_asn1_encode_bool);
    TEST(test_asn1_decode_bool);
    TEST(test_asn1_encode_int);
    TEST(test_asn1_decode_int);
    TEST(test_asn1_encode_bit_string);
    TEST(test_asn1_decode_bit_string);
    TEST(test_asn1_encode_octet_string);
    TEST(test_asn1_encode_null);
    TEST(test_asn1_decode_null);
    TEST(test_asn1_encode_oid);
    TEST(test_asn1_encode_enum);
    TEST(test_asn1_decode_enum);
    TEST(test_asn1_encode_printable_string);
    TEST(test_asn1_encode_ia5_string);

    return 0;
}
