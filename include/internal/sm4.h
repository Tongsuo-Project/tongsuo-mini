/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_INTERNAL_SM4_H)
# define TSM_INTERNAL_SM4_H
# pragma once

# include <stdint.h>
# include <tongsuo/minisuo.h>

# define SM4_KEY_SCHEDULE 32

# pragma pack(1)
typedef struct tsm_sm4_ctx_s {
    uint32_t rk[SM4_KEY_SCHEDULE];
    unsigned char mode;
    unsigned char flags;
    unsigned char block_size;
    unsigned char iv_len;
    unsigned char iv[TSM_MAX_IV_LENGTH];
    int buf_len;                             /* number we have left */
    unsigned char buf[TSM_MAX_BLOCK_LENGTH]; /* saved partial block */
    int final_used;
    unsigned char final[TSM_MAX_BLOCK_LENGTH]; /* possible final block */
} TSM_SM4_CTX;
# pragma pack()

#endif
