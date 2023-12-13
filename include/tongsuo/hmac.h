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

/* Create a new context of HMAC. Should be freed by calling tsm_hmac_ctx_free() after use.  */
void *tsm_hmac_ctx_new(void);
/* Frees up the context ctx of HMAC. */
void tsm_hmac_ctx_free(void *ctx);
/* Initialize the HMAC context with the given key and key length. The hash_alg sets the used hash
 * algorith.
 * Returns TSM_OK on success, error code on failure. */
int tsm_hmac_init(void *ctx, const unsigned char *key, size_t keylen, int hash_alg);
/* Updates the HMAC context with the given data in and data length inlen. Returns TSM_OK for success
 * and others for failure. */
int tsm_hmac_update(void *ctx, const unsigned char *in, size_t inlen);
/* Finalizes the HMAC context and writes the result to out. The length of the result is written to
 * outlen. Returns TSM_OK for success and others for failure. */
int tsm_hmac_final(void *ctx, unsigned char *out, size_t *outlen);
/* Computes the HMAC of the given data in and data length inlen with the given key and key length
 * keylen. The result is written to out. The length of the result is written to outl. The hash_alg
 * sets the used hash algorithm, maybe TSM_HASH_SM3, TSM_HASH_ASCON_HASH or others. Returns
 * TSM_OK for success and others for failure. */
int tsm_hmac_oneshot(int hash_alg, const unsigned char *key, size_t keylen, const unsigned char *in,
                     size_t inlen, unsigned char *out, size_t *outl);

# ifdef __cplusplus
}
# endif
#endif
