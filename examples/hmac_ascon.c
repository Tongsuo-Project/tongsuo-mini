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
#include <assert.h>
#include <tongsuo/minisuo.h>
#include <tongsuo/ascon.h>
#include <tongsuo/mem.h>
#include <tongsuo/hmac.h>

int main(void)
{
    int ret = 1;
    void *ctx = NULL;
    const char *data = "hello world";
    unsigned char *key =
        tsm_hex2buf("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    unsigned char hmac[TSM_ASCON_HMAC_LEN];
    size_t outl;

    if (key == NULL)
        goto err;

    ctx = tsm_hmac_ctx_new();
    if (ctx == NULL) {
        goto err;
    }

    if (tsm_hmac_init(ctx, key, 32, TSM_HASH_ASCON_HASH) != TSM_OK
        || tsm_hmac_update(ctx, (const unsigned char *)data, strlen(data)) != TSM_OK
        || tsm_hmac_final(ctx, hmac, &outl) != TSM_OK) {
        goto err;
    }

    printf("HMAC_ASCON(%s)=", data);

    for (size_t i = 0; i < outl; i++) {
        printf("%02x", hmac[i]);
    }

    printf("\n");

    ret = 0;
err:
    tsm_free(key);
    tsm_hmac_ctx_free(ctx);
    return ret;
}
