/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TONGSUOMINI_SM4_H)
# define TONGSUOMINI_SM4_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <tongsuo/minisuo.h>

void *tsm_sm4_init(int mode, const unsigned char *key, const unsigned char *iv, int flags);
int tsm_sm4_update(void *ctx, const unsigned char *in, int inl, unsigned char *out, int *outl);
int tsm_sm4_final(void *ctx, unsigned char *out, int *outl);
int tsm_sm4_oneshot(int mode, const unsigned char *key, const unsigned char *iv,
                    const unsigned char *in, int inl, unsigned char *out, int *outl, int flags);

# ifdef __cplusplus
}
# endif
#endif
