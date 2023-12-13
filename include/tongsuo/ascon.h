/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_ASCON_H)
# define TSM_ASCON_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <stdlib.h>

# define TSM_ASCON_AEAD_128       0x1
# define TSM_ASCON_AEAD_128A      0x2

# define TSM_ASCON_AEAD_TAG_LEN   16
# define TSM_ASCON_AEAD_KEY_LEN   16
# define TSM_ASCON_AEAD_IV_LEN    16

# define TSM_ASCON_HASH           0x1
# define TSM_ASCON_HASHA          0x2

# define TSM_ASCON_HASH_LEN       32
# define TSM_ASCON_HMAC_LEN       TSM_ASCON_HASH_LEN

/* Create a new context of ascon aead, should be freed by tsm_ascon_aead_ctx_free() after use. */
void *tsm_ascon_aead_ctx_new(void);
/* Frees up the context ctx of ascon aead. */
void tsm_ascon_aead_ctx_free(void *ctx);
/* Initializes the context ctx with type, key, iv and flags. type should be TSM_ASCON_AEAD_128 or
 * TSM_ASCON_AEAD_128A. The length of key and iv should be 16 bytes. flags may be
 * TSM_CIPH_FLAG_ENCRYPT or TSM_CIPH_FLAG_DECRYPT. If you want to encrypt data without padding,
 * flags should be TSM_CIPH_FLAG_ENCRYPT | TSM_CIPH_FLAG_NO_PAD. Returns TSM_OK for success and
 * others for failure. */
int tsm_ascon_aead_init(void *ctx, int type, const unsigned char *key, const unsigned char *iv,
                        int flags);
/* Encrypts or decrypts data at in with the length inl, and retrives the result at out. The number
 * of bytes of result written will be written to the integer at outl. Returns TSM_OK for success and
 * others for failure. */
int tsm_ascon_aead_update(void *ctx, const unsigned char *in, size_t inl, unsigned char *out,
                          size_t *outl);
/* Encrypts or decrypts the "final" data, that is any data that remains in a partial block. The
 * encrypted or decrypted final data is written to out which should have sufficient space for one
 * cipher block, 16 bytes for aead. The number of bytes written is placed in outl. After this
 * function is called the encryption operation is finished and no further calls to
 * tsm_ascon_aead_update() should be made. Returns TSM_OK for success and others for failure. */
int tsm_ascon_aead_final(void *ctx, unsigned char *out, size_t *outl);
/* Set tag before ascon AEAD decryption. */
int tsm_ascon_aead_set_tag(void *ctx, const unsigned char *tag);
/* Get tag after ascon AEAD encryption. */
int tsm_ascon_aead_get_tag(void *ctx, unsigned char *tag);
/* Encrypts or decrypts data at in with length inl, and retrives the result at out. The number of
 * bytes of result written will be written to the integer at outl. The length of key and iv
 * should be 16 bytes. type should be TSM_ASCON_AEAD_128 or TSM_ASCON_AEAD_128A. flags may be
 * TSM_CIPH_FLAG_ENCRYPT or TSM_CIPH_FLAG_DECRYPT. If you want to encrypt data without padding,
 * flags should be TSM_CIPH_FLAG_ENCRYPT | TSM_CIPH_FLAG_NO_PAD. Returns TSM_OK for success and
 * others for failure. */
int tsm_ascon_aead_oneshot(int type, const unsigned char *key, const unsigned char *iv,
                           const unsigned char *ad, size_t adl, const unsigned char *in, size_t inl,
                           unsigned char *out, size_t *outl, int flags);
/* Create ctx of ascon hash. */
void *tsm_ascon_hash_ctx_new(void);
/* Destroy ctx of ascon hash. */
void tsm_ascon_hash_ctx_free(void *ctx);
/* Initialize ctx with type. type should be TSM_ASCON_HASH or TSM_ASCON_HASHA. Returns TSM_OK for
 * success and others for failure. */
int tsm_ascon_hash_init(void *ctx, int type);
/* Hashes inl bytes of data at in into the hash context ctx. This function can be called serveral
 * times on the same ctx to hash more data. Returns TSM_OK for success and others for failure. */
int tsm_ascon_hash_update(void *ctx, const unsigned char *in, size_t inl);
/* Retrieves the hash value from ctx and place it in out. The number of bytes of data written will
 * be written to the integer at outl. If successful, the length of digest should be
 * TSM_ASCON_HASH_LEN. After calling tsm_ascon_hash_final() no additional calls to
 * tsm_ascon_hash_update() can be made. Returns TSM_OK for success and others for failure. */
int tsm_ascon_hash_final(void *ctx, unsigned char *out, size_t *outl);
/* Hashes inl bytes of data at in, and retrieves the hash value at out. type should be
 * TSM_ASCON_HASH or TSM_ASCON_HASHA. The number of bytes of data written will be written to the
 * integer at outl. If successful, the length of digest should be TSM_ASCON_HASH_LEN. Returns TSM_OK
 * for success and others for failure. */
int tsm_ascon_hash_oneshot(int type, const unsigned char *in, size_t inl, unsigned char *out,
                           size_t *outl);
/* Return the method of ascon hash, including create ctx, destroy ctx, etc, maybe used by
 * tsm_hmac_oneshot(). type should be TSM_ASCON_HASH or TSM_ASCON_HASHA. */
void *tsm_ascon_hash_meth(int type);

# ifdef __cplusplus
}
# endif
#endif
