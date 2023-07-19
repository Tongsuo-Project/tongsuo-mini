/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */
#include <string.h>
#include <tongsuo/minisuo.h>

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

int tsm_hex2bin(const char *str, unsigned char *buf, long *buflen)
{
    long i, j;
    long len;

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
