/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */
#include <stdio.h>
#include <string.h>
#include <tongsuo/minisuo.h>
#include <tongsuo/sm3.h>

int main(void)
{
    const char *data = "hello world";
    unsigned char md[TSM_SM3_DIGEST_LEN];

    if (tsm_sm3_oneshot((const unsigned char *)data, strlen(data), md) != TSM_OK) {
        return 1;
    }

    printf("SM3(%s)=", data);

    for (int i = 0; i < TSM_SM3_DIGEST_LEN; i++) {
        printf("%02x", md[i]);
    }

    printf("\n");

    return 0;
}
