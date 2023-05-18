/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

/*
 * ASN.1 DER编解码函数， Tag || Length || Value
 * 返回0表示成功，非0表示失败
 * 输出参数：outl，追加输出缓存区写入的长度
 */

#include "internal/asn1.h"
#include "internal/log.h"
#include <tongsuo/minisuo.h>
#include <stdio.h>
#include <string.h>

int asn1_encode_header_tag(unsigned char **out, size_t *outl, int tag)
{
    if (out && *out) {
        **out = tag;
        (*out)++;
    }

    *outl += 1;

    return 0;
}

int asn1_decode_header_tag(unsigned char **in, size_t inlen, int *tag)
{
    if (inlen < 1)
        return ERR_OUT_OF_DATA;

    *tag = **in;
    (*in)++;

    return 0;
}

int asn1_encode_header_len(unsigned char **out, size_t *outl, size_t len)
{
    int n = 0;

    if (len < 0x80) {
        if (out && *out) {
            **out = len;
            (*out)++;
        }

        *outl += 1;
        return 0;
    }

    while (len) {
        n++;
        len >>= 8;
    }

    if (n > 4)
        return ERR_INTERNAL_ERROR;

    *outl += n + 1;

    if (out && *out) {
        **out = 0x80 | n;
        (*out)++;
        while (n--) {
            **out = len >> (n * 8);
            (*out)++;
        }
    }

    return 0;
}

int asn1_decode_header_len(unsigned char **in, size_t inlen, size_t *len)
{
    unsigned char *end = *in + inlen;

    if (inlen < 1)
        return ERR_OUT_OF_DATA;

    if ((**in & 0x80) == 0) {
        *len = *(*in)++;
    } else {
        switch (**in & 0x7F) {
        case 1:
            if (inlen < 2)
                return ERR_OUT_OF_DATA;

            *len = (*in)[1];
            (*in) += 2;
            break;

        case 2:
            if (inlen < 3)
                return ERR_OUT_OF_DATA;

            *len = ((size_t)(*in)[1] << 8) | (*in)[2];
            (*in) += 3;
            break;

        case 3:
            if (inlen < 4)
                return ERR_OUT_OF_DATA;

            *len = ((size_t)(*in)[1] << 16) | ((size_t)(*in)[2] << 8) | (*in)[3];
            (*in) += 4;
            break;

        case 4:
            if (inlen < 5)
                return ERR_OUT_OF_DATA;

            *len = ((size_t)(*in)[1] << 24) | ((size_t)(*in)[2] << 16) | ((size_t)(*in)[3] << 8)
                   | (*in)[4];
            (*in) += 5;
            break;

        default:
            return ERR_INVALID_ASN1_LENGTH;
        }
    }

    if (*len > (size_t)(end - *in))
        return ERR_OUT_OF_DATA;

    return 0;
}

int asn1_encode_header(unsigned char **out, size_t *outl, int tag, size_t len)
{
    int err;

    if ((err = asn1_encode_header_tag(out, outl, tag)) != 0
        || (err = asn1_encode_header_len(out, outl, len)) != 0)
        return err;

    return 0;
}

int asn1_decode_header(unsigned char **in, size_t inlen, int tag, size_t *len)
{
    int t;

    if (asn1_decode_header_tag(in, inlen, &t) || t != tag)
        return ERR_UNEXPECTED_ASN1_TAG;

    if (len)
        return asn1_decode_header_len(in, inlen - 1, len);

    return 0;
}

int asn1_encode_bool(unsigned char **out, size_t *outl, int val)
{
    int err;

    if ((err = asn1_encode_header(out, outl, TONGSUO_ASN1_BOOLEAN, 1)) != 0)
        return err;

    if (out && *out) {
        **out = (val == 0) ? 0x00 : 0xFF;
        (*out)++;
    }

    *outl += 1;
    return 0;
}

int asn1_decode_bool(unsigned char **in, size_t inlen, int *val)
{
    size_t len;

    if (asn1_decode_header(in, inlen, TONGSUO_ASN1_BOOLEAN, &len) || len != 1)
        return ERR_INVALID_ASN1_LENGTH;

    *val = (**in == 0xFF) ? 1 : 0;
    (*in)++;

    return 0;
}

static int asn1_encode_tag_int(unsigned char **out, size_t *outl, int tag, int val)
{
    unsigned char buf[sizeof(int) + 1];
    int err, len;

    if (val < 0)
        return ERR_INVALID_ASN1_VALUE;

    len = 0;
    do {
        buf[len++] = val & 0xFF;
        val >>= 8;
    } while (val > 0);

    if (buf[len - 1] & 0x80)
        buf[len++] = 0;

    if ((err = asn1_encode_header(out, outl, tag, len)) != 0)
        return err;

    *outl += len;

    if (out && *out) {
        while (len--)
            *(*out)++ = buf[len];
    }

    return 0;
}

int asn1_encode_int(unsigned char **out, size_t *outl, int val)
{
    return asn1_encode_tag_int(out, outl, TONGSUO_ASN1_INTEGER, val);
}

int asn1_encode_enum(unsigned char **out, size_t *outl, int val)
{
    return asn1_encode_tag_int(out, outl, TONGSUO_ASN1_ENUMERATED, val);
}

int asn1_decode_tag_int(unsigned char **in, size_t inlen, int tag, int *val)
{
    CHECKP(in);
    CHECKP(*in);
    CHECKP(val);

    int err;
    size_t len;

    if ((err = asn1_decode_header(in, inlen, tag, &len)) != 0)
        return err;

    /*
     * len==0 is malformed (0 must be represented as 020100 for INTEGER,
     * or 0A0100 for ENUMERATED tags
     */
    if (len == 0)
        return ERR_INVALID_ASN1_LENGTH;

    /* Reject negative integer */
    if ((**in & 0x80) != 0)
        return ERR_INVALID_ASN1_LENGTH;

    /* Skip leading zeros. */
    while (len > 0 && **in == 0) {
        ++(*in);
        --len;
    }

    /* Reject integers that don't fit in an int. This code assumes that
     * the int type has no padding bit. */
    if (len > sizeof(int))
        return ERR_INVALID_ASN1_LENGTH;

    if (len == sizeof(int) && (**in & 0x80) != 0)
        return ERR_INVALID_ASN1_LENGTH;

    *val = 0;
    while (len-- > 0) {
        *val = (*val << 8) | **in;
        (*in)++;
    }

    return 0;
}

int asn1_decode_int(unsigned char **in, size_t inlen, int *val)
{
    return asn1_decode_tag_int(in, inlen, TONGSUO_ASN1_INTEGER, val);
}

int asn1_decode_enum(unsigned char **in, size_t inlen, int *val)
{
    return asn1_decode_tag_int(in, inlen, TONGSUO_ASN1_ENUMERATED, val);
}

int asn1_encode_bit_string(unsigned char **out, size_t *outl, const unsigned char *bs, size_t nbits)
{
    size_t len, padding;
    int err;

    len = 1 + (nbits + 7) / 8;
    padding = nbits % 8;

    if ((err = asn1_encode_header(out, outl, TONGSUO_ASN1_BIT_STRING, len)) != 0)
        return err;

    *outl += len;

    if (out && *out) {
        *(*out)++ = padding;
        memcpy(*out, bs, len - 1);
        *out += len - 1;
    }

    return 0;
}

int asn1_decode_bit_string(unsigned char **in, size_t inlen, unsigned char *bs, size_t *nbits)
{
    size_t len, padding;
    int err;

    if ((err = asn1_decode_header(in, inlen, TONGSUO_ASN1_BIT_STRING, &len)) != 0)
        return err;

    if (len < 1)
        return ERR_INVALID_ASN1_LENGTH;

    padding = **in;
    if (padding > 7)
        return ERR_INVALID_ASN1_VALUE;

    len -= 1;
    (*in)++;

    *in += len;
    if (bs)
        memcpy(bs, *in, len);

    *nbits = len * 8 - padding;

    return 0;
}

int asn1_encode_null(unsigned char **out, size_t *outl)
{
    int err;

    if ((err = asn1_encode_header(out, outl, TONGSUO_ASN1_NULL, 0)) != 0)
        return err;

    return 0;
}

int asn1_decode_null(unsigned char **in, size_t inlen)
{
    size_t len;

    if (asn1_decode_header(in, inlen, TONGSUO_ASN1_NULL, &len) || len != 0)
        return ERR_INVALID_ASN1_LENGTH;

    return 0;
}

static int asn1_encode_tag_string(unsigned char **out, size_t *outl, int tag,
                                  const unsigned char *buf, size_t buflen)
{
    int err;

    if ((err = asn1_encode_header(out, outl, tag, buflen)) != 0)
        return err;

    *outl += buflen;

    if (out && *out) {
        memcpy(*out, buf, buflen);
        *out += buflen;
    }

    return 0;
}

int asn1_encode_octet_string(unsigned char **out, size_t *outl, const unsigned char *buf,
                             size_t buflen)
{
    return asn1_encode_tag_string(out, outl, TONGSUO_ASN1_OCTET_STRING, buf, buflen);
}

int asn1_encode_printable_string(unsigned char **out, size_t *outl, const unsigned char *buf,
                                 size_t buflen)
{
    return asn1_encode_tag_string(out, outl, TONGSUO_ASN1_PRINTABLE_STRING, buf, buflen);
}

int asn1_encode_ia5_string(unsigned char **out, size_t *outl, const unsigned char *buf,
                           size_t buflen)
{
    return asn1_encode_tag_string(out, outl, TONGSUO_ASN1_IA5_STRING, buf, buflen);
}

int asn1_encode_oid(unsigned char **out, size_t *outl, const unsigned char *oid, size_t oidlen)
{
    return asn1_encode_tag_string(out, outl, TONGSUO_ASN1_OBJECT_IDENTIFIER, oid, oidlen);
}
