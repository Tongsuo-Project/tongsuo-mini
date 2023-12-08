/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */
#include <string.h>
#include "internal/log.h"
#include <tongsuo/mem.h>
#include <tongsuo/minisuo.h>

void *tsm_alloc(size_t size)
{
    void *ptr = malloc(size);
    LOGD("malloc %p:%u", ptr, size);
    return ptr;
}

void *tsm_calloc(size_t size)
{
    void *ptr;

    ptr = tsm_alloc(size);
    if (ptr)
        tsm_memzero(ptr, size);

    return ptr;
}

void tsm_free(void *ptr)
{
    LOGD("free %p", ptr);
    if (ptr == NULL)
        return;
    free(ptr);
}

void tsm_memzero(void *ptr, size_t size)
{
    (void)memset(ptr, 0, size);
}

static int tsm_hexchar2int(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

int tsm_hex2bin(const char *str, unsigned char *buf, size_t *buflen)
{
    size_t i, j;
    size_t len;

    len = strlen(str);
    if (len & 1) {
        return TSM_ERR_INVALID_HEX_STR;
    }
    len /= 2;

    if (buf == NULL) {
        *buflen = len;
        return TSM_OK;
    }

    if (*buflen < len) {
        *buflen = len;
        return TSM_ERR_BUFFER_TOO_SMALL;
    }

    memset(buf, 0, *buflen);

    for (i = 0, j = 0; i < len; i++) {
        int k;

        k = tsm_hexchar2int(str[i * 2]);
        if (k < 0)
            return TSM_ERR_INVALID_HEX_STR;

        buf[j] = k << 4;

        k = tsm_hexchar2int(str[i * 2 + 1]);
        if (k < 0)
            return TSM_ERR_INVALID_HEX_STR;

        buf[j] |= k;
        j++;
    }

    *buflen = len;

    return TSM_OK;
}

unsigned char *tsm_hex2buf(const char *str)
{
    size_t len;
    unsigned char *buf;

    if (str == NULL)
        return NULL;

    len = strlen(str);
    if (len & 1)
        return NULL;

    len /= 2;
    buf = tsm_alloc(len);
    if (buf == NULL)
        return NULL;

    if (tsm_hex2bin(str, buf, &len) != TSM_OK) {
        tsm_free(buf);
        return NULL;
    }

    return buf;
}

TSM_STR *tsm_str_new(const uint8_t *data, size_t len)
{
    TSM_STR *buf;
    uint8_t *tmp;

    buf = tsm_calloc(sizeof(*buf));
    if (buf == NULL)
        return NULL;

    tmp = tsm_alloc(len);
    if (tmp == NULL) {
        tsm_free(tmp);
        return NULL;
    }

    memcpy(tmp, data, len);
    buf->length = len;
    buf->s = tmp;

    return buf;
}

TSM_STR *tsm_str_dup(TSM_STR *buf)
{
    if (buf == NULL)
        return NULL;

    return tsm_str_new(buf->s, buf->length);
}

int tsm_str_equal(TSM_STR *a, TSM_STR *b)
{
    if (a == NULL || b == NULL)
        return 0;

    if (a->length == b->length && memcmp(a->s, b->s, a->length) == 0)
        return 1;

    return 0;
}

void tsm_str_free(TSM_STR *buf)
{
    if (buf == NULL)
        return;

    tsm_free((void *)buf->s);
    tsm_free(buf);
}

TSM_STR *tsm_str_const(const uint8_t *data, size_t len)
{
    static int pos = 0;
    static TSM_STR tb[10];
    if (pos == 10)
        pos = 0;
    tb[pos].length = len;
    tb[pos].s = data;
    return &tb[pos++];
}

TSM_STR *tsm_str(const char *string)
{
    return tsm_str_const((const uint8_t *)string, strlen(string));
}
