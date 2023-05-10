/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TONGSUOMINI_ERROR_H)
# define TONGSUOMINI_ERROR_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

enum {
    ERR_NO_ERROR = 0,
    ERR_INTERNAL_ERROR,
    ERR_PASS_NULL_PARAM,
    ERR_MALLOC_FAILED,
    ERR_OUT_OF_DATA,
    ERR_BUFFER_OVERFLOW,
    ERR_UNEXPECTED_ASN1_TAG,
    ERR_INVALID_ASN1_LENGTH,
    ERR_INVALID_ASN1_VALUE,
};

const char *tsm_error_string(int err);

# ifdef __cplusplus
}
# endif
#endif
