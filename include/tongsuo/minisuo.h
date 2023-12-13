/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_MINISUO_H)
# define TSM_MINISUO_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <stdlib.h>

# define TONGSUO_IS_MINI       1

# define TSM_VERSION_MAJOR     0
# define TSM_VERSION_MINOR     9
# define TSM_VERSION_PATCH     0
/* 0x00, dev
 * 0x1~0xfe, pre1~pre254
 * 0xff, release */
# define TSM_VERSION_TAG 0
# define TONGSUO_MINI_VERSION                                                                      \
     ((TSM_VERSION_MAJOR << 24) | (TSM_VERSION_MINOR << 16) | (TSM_VERSION_PATCH << 8)             \
      | TSM_VERSION_TAG)

/* Supported cipher modes. */
# define TSM_CIPH_MODE_STREAM 0x0
# define TSM_CIPH_MODE_ECB    0x1
# define TSM_CIPH_MODE_CBC    0x2
# define TSM_CIPH_MODE_CFB    0x3
# define TSM_CIPH_MODE_OFB    0x4
# define TSM_CIPH_MODE_CTR    0x5
# define TSM_CIPH_MODE_GCM    0x6
# define TSM_CIPH_MODE_CCM    0x7

/* Supported cipher flags. */
# define TSM_CIPH_FLAG_ENCRYPT 0x1
# define TSM_CIPH_FLAG_DECRYPT 0x2
# define TSM_CIPH_FLAG_NO_PAD  0x4

# define TSM_MAX_IV_LENGTH     16
# define TSM_MAX_BLOCK_LENGTH  32

/* Supported hash algorithms. */
enum {
    TSM_HASH_SM3 = 1,
    TSM_HASH_ASCON_HASH,
    TSM_HASH_ASCON_HASHA,
};

/* All error codes are defined here.
 * Most of APIs return TSM_OK on success, specific error code on failure. */
enum {
    TSM_FAILED = -1,
    TSM_OK = 0,
    TSM_ERR_INTERNAL_ERROR,
    TSM_ERR_PASS_NULL_PARAM,
    TSM_ERR_MALLOC_FAILED,
    TSM_ERR_OUT_OF_DATA,
    TSM_ERR_BUFFER_OVERFLOW,
    TSM_ERR_BUFFER_TOO_SMALL,
    TSM_ERR_UNEXPECTED_ASN1_TAG,
    TSM_ERR_INVALID_ASN1_LENGTH,
    TSM_ERR_INVALID_ASN1_VALUE,
    TSM_ERR_WRONG_FINAL_BLOCK_LENGTH,
    TSM_ERR_BAD_DECRYPT,
    TSM_ERR_WRONG_CIPH_MODE,
    TSM_ERR_INVALID_HEX_STR,
    TSM_ERR_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH,
    TSM_ERR_INVALID_AEAD_TAG_LENGTH,
    TSM_ERR_INVALID_OPERATION,
    TSM_ERR_INVALID_ASCON_SCHEME,
    TSM_ERR_AEAD_VERIFY_FAILED,
    TSM_ERR_INVALID_HASH_SIZE,
    TSM_ERR_INVALID_HASH_ALGORITHM,
    TSM_ERR_NOT_FOUND,
    TSM_ERR_INVALID_SEQ,
    TSM_ERR_REPLAYED_SEQ,
    TSM_ERR_ALGORITHM_NOT_SUPPORTED,
};

/* Converts error code to error string. */
const char *tsm_err2str(int err);
/* Returns version text of tongsuo-mini. */
const char *tsm_version_text(void);

# ifdef __cplusplus
}
# endif
#endif
