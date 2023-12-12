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

int main(void)
{
    void *ctx = NULL;
    const char *data = "hello world";
    unsigned char md[TSM_ASCON_HASH_LEN];
    size_t outl;

    ctx = tsm_ascon_hash_ctx_new();
    if (ctx == NULL) {
        return 1;
    }

    if (tsm_ascon_hash_init(ctx, TSM_ASCON_HASH) != TSM_OK
        || tsm_ascon_hash_update(ctx, (const unsigned char *)data, strlen(data)) != TSM_OK
        || tsm_ascon_hash_final(ctx, md, &outl) != TSM_OK) {
        tsm_ascon_hash_ctx_free(ctx);
        return 1;
    }

    tsm_ascon_hash_ctx_free(ctx);

    printf("ASCON_HASH(%s)=", data);

    for (size_t i = 0; i < outl; i++) {
        printf("%02x", md[i]);
    }

    printf("\n");

    return 0;
}
/* cc ascon_hash.c -I/opt/tongsuo-mini/include -L/opt/tongsuo-mini/lib -ltongsuo-mini -Wl,-rpath \
/opt/tongsuo-mini/lib -o ascon_hash
 */
