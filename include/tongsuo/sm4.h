/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_SM4_H)
# define TSM_SM4_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <stdlib.h>

/* Create a new context of sm4. The context should be freed by calling tsm_sm4_ctx_free() after use.
 */
void *tsm_sm4_ctx_new(void);
/* Frees up the context of sm4. */
void tsm_sm4_ctx_free(void *ctx);
/* Initialize the sm4 context. Note: only mode TSM_CIPH_MODE_CBC is supported now. The length of key
 * should be 128 bits(16 bytes). iv is set on demand. flags can contain multiple flags bitwise XOR;
 * TSM_CIPH_FLAG_ENCRYPT means performing encryption, TSM_CIPH_FLAG_DECRYPT means performing
 * decryption, TSM_CIPH_FLAG_NO_PAD means no padding. Returns TSM_OK on success, error code on
 * error. */
int tsm_sm4_init(void *ctx, int mode, const unsigned char *key, const unsigned char *iv, int flags);
/* Updates the sm4 context with the given data in and data length inl. The result is written to out
 * with the actual length to outl. Returns TSM_OK on success, error code on error. */
int tsm_sm4_update(void *ctx, const unsigned char *in, size_t inl, unsigned char *out,
                   size_t *outl);
/* Finalizes the sm4 encryption or decryption and writes the "final" data to out with the actual
 * length to outl. Returns TSM_OK on success, error code on error. */
int tsm_sm4_final(void *ctx, unsigned char *out, size_t *outl);
/* Encrypts or decrypts the given data in with the length inl. The result is written to out with the
 * actual length to outl. The length of key should be 128 bits(16 bytes). iv is set on demand. flags
 * can contain multiple flags bitwise XOR; TSM_CIPH_FLAG_ENCRYPT means performing encryption,
 * TSM_CIPH_FLAG_DECRYPT means performing decryption, TSM_CIPH_FLAG_NO_PAD means no padding.
 * Returns TSM_OK on success, error code on error. */
int tsm_sm4_oneshot(int mode, const unsigned char *key, const unsigned char *iv,
                    const unsigned char *in, size_t inl, unsigned char *out, size_t *outl,
                    int flags);

# ifdef __cplusplus
}
# endif
#endif
