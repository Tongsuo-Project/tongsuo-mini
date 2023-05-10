/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <tongsuo/error.h>
#include <stdlib.h>

static const char *errstr[] = {
    [ERR_NO_ERROR] = "Success",
    [ERR_INTERNAL_ERROR] = "Internal error",
    [ERR_PASS_NULL_PARAM] = "Pass null param",
    [ERR_MALLOC_FAILED] = "Malloc failed",
    [ERR_OUT_OF_DATA] = "Out of data",
    [ERR_BUFFER_OVERFLOW] = "Buffer overflow",
    [ERR_UNEXPECTED_ASN1_TAG] = "Unexpected ASN1 tag",
    [ERR_INVALID_ASN1_LENGTH] = "Invalid ASN1 length",
    [ERR_INVALID_ASN1_VALUE] = "Invalid ASN1 value",
};

const char *tsm_error_string(int err)
{
    if (err < ERR_NO_ERROR)
        return NULL;

    return errstr[err];
}
