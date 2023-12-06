/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_HMAC_H)
# define TSM_HMAC_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <stdlib.h>

void *tsm_hmac_ctx_new(void);
void tsm_hmac_ctx_free(void *ctx);

int tsm_hmac_init(void *ctx, const unsigned char *key, size_t keylen, void *meth);
int tsm_hmac_update(void *ctx, const unsigned char *in, size_t inlen);
int tsm_hmac_final(void *ctx, unsigned char *out, size_t *outlen);

int tsm_hmac(void *meth, const unsigned char *key, size_t keylen, const unsigned char *in,
             size_t inlen, unsigned char *out, size_t *outl);

# ifdef __cplusplus
}
# endif
#endif
