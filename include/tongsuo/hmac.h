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
/* Initialize the HMAC context with the given key and key length. The meth sets the used hash
 * methods. For example, if you want to use ascon hash, the meth can be obtained by calling
 * tsm_ascon_hash_meth(). Returns TSM_OK for success and others for failure. */
int tsm_hmac_init(void *ctx, const unsigned char *key, size_t keylen, void *meth);
/* Updates the HMAC context with the given data in and data length inlen. Returns TSM_OK for success
 * and others for failure. */
int tsm_hmac_update(void *ctx, const unsigned char *in, size_t inlen);
/* Finalizes the HMAC context and writes the result to out. The length of the result is written to
 * outlen. Returns TSM_OK for success and others for failure. */
int tsm_hmac_final(void *ctx, unsigned char *out, size_t *outlen);
/* Computes the HMAC of the given data in and data length inlen with the given key and key length
 * keylen. The result is written to out. The length of the result is written to outl. The meth sets
 * the used hash methods. For example, if you want to use ascon hash, the meth can be obtained by
 * calling tsm_ascon_hash_meth(). Returns TSM_OK for success and others for failure. */
int tsm_hmac_oneshot(void *meth, const unsigned char *key, size_t keylen, const unsigned char *in,
                     size_t inlen, unsigned char *out, size_t *outl);

# ifdef __cplusplus
}
# endif
#endif
