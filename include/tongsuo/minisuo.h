/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TONGSUOMINI_MINISUO_H)
# define TONGSUOMINI_MINISUO_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# define TSM_CIPH_MODE_STREAM  0x0
# define TSM_CIPH_MODE_ECB     0x1
# define TSM_CIPH_MODE_CBC     0x2
# define TSM_CIPH_MODE_CFB     0x3
# define TSM_CIPH_MODE_OFB     0x4
# define TSM_CIPH_MODE_CTR     0x5
# define TSM_CIPH_MODE_GCM     0x6
# define TSM_CIPH_MODE_CCM     0x7

# define TSM_CIPH_FLAG_DECRYPT 0x0
# define TSM_CIPH_FLAG_ENCRYPT 0x1
# define TSM_CIPH_FLAG_NO_PAD  0x2

# define TSM_MAX_IV_LENGTH     16
# define TSM_MAX_BLOCK_LENGTH  32

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
};

const char *tsm_version(void);
const char *tsm_err2str(int err);

# ifdef __cplusplus
}
# endif
#endif
