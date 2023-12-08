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

/* Create a new context of sm3. The context should be freed by calling tsm_sm3_ctx_free() after use.
 */
void *tsm_sm3_ctx_new(void);
/* Frees up the context of sm3. */
void tsm_sm3_ctx_free(void *ctx);
/* Initialize the sm3 context. Returns TSM_OK on success, error code on error. */
int tsm_sm3_init(void *ctx);
/* Updates the sm3 context with the given data in and data length len. Returns TSM_OK on success,
 * error code on error. */
int tsm_sm3_update(void *ctx, const void *data, size_t len);
/* Finalizes the sm3 context and writes the result to md. The buffer md must hold TSM_SM3_DIGEST_LEN
 * bytes. Returns TSM_OK on success, error code on error. */
int tsm_sm3_final(void *ctx, unsigned char *md);
/* Perform SM3 transformation with the given data data and data length num. */
void tsm_sm3_transform(void *ctx, const void *data, size_t num);
/* Computes the SM3 hash of the given data data and data length len. The result is written to md.
 * The buffer md must hold TSM_SM3_DIGEST_LEN bytes. Returns TSM_OK on success, error code on error.
 */
int tsm_sm3_oneshot(const void *data, size_t len, unsigned char *md);

# ifdef __cplusplus
}
# endif
#endif
