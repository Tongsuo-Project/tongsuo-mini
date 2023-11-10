/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_INTERNAL_ASN1_H)
# define TSM_INTERNAL_ASN1_H
# pragma once

# include <stddef.h>

# define TONGSUO_ASN1_BOOLEAN           0x01
# define TONGSUO_ASN1_INTEGER           0x02
# define TONGSUO_ASN1_BIT_STRING        0x03
# define TONGSUO_ASN1_OCTET_STRING      0x04
# define TONGSUO_ASN1_NULL              0x05
# define TONGSUO_ASN1_OBJECT_IDENTIFIER 0x06
# define TONGSUO_ASN1_ENUMERATED        0x0A
# define TONGSUO_ASN1_UTF8_STRING       0x0C
# define TONGSUO_ASN1_SEQUENCE          0x10
# define TONGSUO_ASN1_SET               0x11
# define TONGSUO_ASN1_PRINTABLE_STRING  0x13
# define TONGSUO_ASN1_T61_STRING        0x14
# define TONGSUO_ASN1_IA5_STRING        0x16
# define TONGSUO_ASN1_UTC_TIME          0x17
# define TONGSUO_ASN1_GENERALIZED_TIME  0x18
# define TONGSUO_ASN1_UNIVERSAL_STRING  0x1C
# define TONGSUO_ASN1_BMP_STRING        0x1E

# define TONGSUO_ASN1_PRIMITIVE         0x00
# define TONGSUO_ASN1_CONSTRUCTED       0x20
# define TONGSUO_ASN1_CONTEXT_SPECIFIC  0x80

typedef struct {
    unsigned char *p;
    size_t len;
    unsigned char padding;
} ts_asn1_bitstring;

int asn1_encode_header_tag(unsigned char **out, size_t *outl, int tag);
int asn1_decode_header_tag(unsigned char **in, size_t inlen, int *tag);
int asn1_encode_header_len(unsigned char **out, size_t *outl, size_t len);
int asn1_decode_header_len(unsigned char **in, size_t inlen, size_t *len);
int asn1_encode_header(unsigned char **out, size_t *outl, int tag, size_t len);
int asn1_decode_header(unsigned char **in, size_t inlen, int tag, size_t *len);

int asn1_encode_bool(unsigned char **out, size_t *outl, int val);
int asn1_decode_bool(unsigned char **in, size_t inlen, int *val);

int asn1_encode_int(unsigned char **out, size_t *outl, int val);
int asn1_decode_int(unsigned char **in, size_t inlen, int *val);

int asn1_encode_bit_string(unsigned char **out, size_t *outl, const unsigned char *bs,
                           size_t nbits);
int asn1_decode_bit_string(unsigned char **in, size_t inlen, unsigned char *bs, size_t *nbits);

int asn1_encode_octet_string(unsigned char **out, size_t *outl, const unsigned char *buf,
                             size_t buflen);

int asn1_encode_null(unsigned char **out, size_t *outl);
int asn1_decode_null(unsigned char **in, size_t inlen);

int asn1_encode_oid(unsigned char **out, size_t *outl, const unsigned char *oid, size_t oidlen);

int asn1_encode_enum(unsigned char **out, size_t *outl, int val);
int asn1_decode_enum(unsigned char **in, size_t inlen, int *val);

int asn1_encode_printable_string(unsigned char **out, size_t *outl, const unsigned char *buf,
                                 size_t buflen);

int asn1_encode_ia5_string(unsigned char **out, size_t *outl, const unsigned char *buf,
                           size_t buflen);
#endif
