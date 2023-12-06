/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_SM3_H)
# define TSM_SM3_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <stdlib.h>

# define TSM_SM3_DIGEST_LEN  32

# define TSM_SM3_CBLOCK      64
# define TSM_SM3_LBLOCK      16

typedef struct {
   unsigned int A, B, C, D, E, F, G, H;
   unsigned int Nl, Nh;
   unsigned int data[TSM_SM3_LBLOCK];
   unsigned int num;
} tsm_sm3_ctx;

tsm_sm3_ctx *tsm_sm3_init(void);
int tsm_sm3_update(tsm_sm3_ctx *c, const void *data, size_t len);
int tsm_sm3_final(tsm_sm3_ctx *c, unsigned char *md);
void tsm_sm3_transform(tsm_sm3_ctx *c, const void *data, size_t num);
int tsm_sm3_oneshot(const void *data, size_t len, unsigned char *md);

# ifdef __cplusplus
}
# endif
#endif
