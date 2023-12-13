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

int main(void)
{
    int ret = 1;
    void *ctx = NULL;
    const char *plaintext = "hello world";
    unsigned char *key = tsm_hex2buf("0123456789abcdef0123456789abcdef");
    unsigned char *iv = tsm_hex2buf("0123456789abcdef0123456789abcdef");
    unsigned char out[1024];
    size_t outl, tmplen;

    ctx = tsm_ascon_aead_ctx_new();
    if (ctx == NULL) {
        goto err;
    }

    if (tsm_ascon_aead_init(ctx, TSM_ASCON_AEAD_128, key, iv, TSM_CIPH_FLAG_ENCRYPT) != TSM_OK
        || tsm_ascon_aead_update(ctx,
                                 (const unsigned char *)plaintext,
                                 strlen(plaintext),
                                 out,
                                 &outl)
               != TSM_OK
        || tsm_ascon_aead_final(ctx, out + outl, &tmplen) != TSM_OK) {
        goto err;
    }

    outl += tmplen;

    printf("ASCON_AEAD_Encrypt(%s)=", plaintext);

    for (size_t i = 0; i < outl; i++) {
        printf("%02x", out[i]);
    }

    printf("\n");

    ret = 0;
err:
    tsm_ascon_aead_ctx_free(ctx);
    tsm_free(key);
    tsm_free(iv);
    return ret;
}
/* cc ascon_aead_enc.c -I/opt/tongsuo-mini/include -L/opt/tongsuo-mini/lib -ltongsuo-mini \
-Wl,-rpath /opt/tongsuo-mini/lib -o ascon_aead_enc
 */
