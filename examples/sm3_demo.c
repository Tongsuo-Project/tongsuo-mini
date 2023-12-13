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
    void *ctx = NULL;
    const char *data1 = "hello ";
    const char *data2 = "world";
    unsigned char md[TSM_SM3_DIGEST_LEN];

    ctx = tsm_sm3_ctx_new();
    if (ctx == NULL) {
        return 1;
    }

    if (tsm_sm3_init(ctx) != TSM_OK
        || tsm_sm3_update(ctx, (const unsigned char *)data1, strlen(data1)) != TSM_OK
        || tsm_sm3_update(ctx, (const unsigned char *)data2, strlen(data2)) != TSM_OK
        || tsm_sm3_final(ctx, md, NULL) != TSM_OK) {
        tsm_sm3_ctx_free(ctx);
        return 1;
    }

    tsm_sm3_ctx_free(ctx);

    printf("SM3(%s%s)=", data1, data2);

    for (int i = 0; i < TSM_SM3_DIGEST_LEN; i++) {
        printf("%02x", md[i]);
    }

    printf("\n");

    return 0;
}
