/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_INTERNAL_SM3_H)
# define TSM_INTERNAL_SM3_H
# pragma once

# define TSM_SM3_CBLOCK 64
# define TSM_SM3_LBLOCK 16

# pragma pack(1)
typedef struct tsm_sm3_ctx_s {
    unsigned int A, B, C, D, E, F, G, H;
    unsigned int Nl, Nh;
    unsigned int data[TSM_SM3_LBLOCK];
    unsigned int num;
} TSM_SM3_CTX;
# pragma pack()

#endif
