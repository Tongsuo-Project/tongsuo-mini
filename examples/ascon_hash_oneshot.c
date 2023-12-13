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
#include <tongsuo/ascon.h>

int main(void)
{
    const char *data = "hello world";
    unsigned char md[TSM_ASCON_HASH_LEN];
    size_t outl;

    if (tsm_ascon_hash_oneshot(TSM_HASH_ASCON_HASH, (const unsigned char *)data, strlen(data), md,
                               &outl)
        != TSM_OK) {
        return 1;
    }

    printf("ASCON_HASH(%s)=", data);

    for (size_t i = 0; i < outl; i++) {
        printf("%02x", md[i]);
    }

    printf("\n");

    return 0;
}
