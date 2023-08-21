/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TONGSUOMINI_ASCON_H)
# define TONGSUOMINI_ASCON_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <tongsuo/minisuo.h>

# define TSM_ASCON_AEAD_128     0x1
# define TSM_ASCON_AEAD_128A    0x2

# define TSM_ASCON_AEAD_TAG_LEN 16

void *tsm_ascon_aead_init(int scheme, const unsigned char *key, const unsigned char *nonce,
                          int flags);
int tsm_ascon_aead_update(void *ctx, const unsigned char *in, int inl, unsigned char *out,
                          int *outl);
int tsm_ascon_aead_final(void *ctx, unsigned char *out, int *outl);
void tsm_ascon_aead_clean(void *ctx);

int tsm_ascon_aead_set_tag(void *ctx, const unsigned char *tag);
int tsm_ascon_aead_get_tag(void *ctx, unsigned char *tag);

int tsm_ascon_aead_oneshot(int scheme, const unsigned char *key, const unsigned char *nonce,
                           const unsigned char *ad, int adl, const unsigned char *in, int inl,
                           unsigned char *out, int *outl, int flags);

# ifdef __cplusplus
}
# endif
#endif
