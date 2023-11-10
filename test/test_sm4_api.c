/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <string.h>
#include "test.h"
#include <tongsuo/sm4.h>

static int test_sm4_crypt(int idx)
{
    void *ctx = NULL;
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char iv[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char plain[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA,
        0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
        0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    };
    unsigned char out[32];
    unsigned char cipher[32] = {
        0x26, 0x77, 0xF4, 0x6B, 0x09, 0xC1, 0x22, 0xCC, 0x97, 0x55, 0x33,
        0x10, 0x5B, 0xD4, 0xA2, 0x2A, 0xF6, 0x12, 0x5F, 0x72, 0x75, 0xCE,
        0x55, 0x2C, 0x3A, 0x2B, 0xBC, 0xF5, 0x33, 0xDE, 0x8A, 0x3B,
    };
    size_t outlen, tmplen;

    if (idx == 0) {
        ctx =
            tsm_sm4_init(TSM_CIPH_MODE_CBC, key, iv, TSM_CIPH_FLAG_ENCRYPT | TSM_CIPH_FLAG_NO_PAD);
        ASSERT(ctx != NULL);

        ASSERT_OK(tsm_sm4_update(ctx, plain, sizeof(plain), out, &outlen));
        ASSERT_OK(tsm_sm4_final(ctx, out + outlen, &tmplen));

        ASSERT(memcmp(out, cipher, sizeof(cipher)) == 0);
    } else if (idx == 1) {
        ctx =
            tsm_sm4_init(TSM_CIPH_MODE_CBC, key, iv, TSM_CIPH_FLAG_DECRYPT | TSM_CIPH_FLAG_NO_PAD);
        ASSERT(ctx != NULL);

        ASSERT_OK(tsm_sm4_update(ctx, cipher, sizeof(cipher), out, &outlen));
        ASSERT_OK(tsm_sm4_final(ctx, out + outlen, &tmplen));

        ASSERT(memcmp(out, plain, sizeof(plain)) == 0);

    } else if (idx == 2) {
        ASSERT_OK(tsm_sm4_oneshot(TSM_CIPH_MODE_CBC, key, iv, plain, sizeof(plain), out, &outlen,
                                  TSM_CIPH_FLAG_ENCRYPT | TSM_CIPH_FLAG_NO_PAD));
        ASSERT(memcmp(out, cipher, sizeof(cipher)) == 0);
    } else if (idx == 3) {
        ASSERT_OK(tsm_sm4_oneshot(TSM_CIPH_MODE_CBC, key, iv, cipher, sizeof(cipher), out, &outlen,
                                  TSM_CIPH_FLAG_DECRYPT | TSM_CIPH_FLAG_NO_PAD));
        ASSERT(memcmp(out, plain, sizeof(plain)) == 0);
    }

    return TSM_OK;
}

int main(void)
{
    TESTS(test_sm4_crypt, 4);

    return TSM_OK;
}
