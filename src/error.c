/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <tongsuo/minisuo.h>
#include <stdlib.h>

#ifdef TSM_ERRSTR
static const char *errstr[] = {
    [TSM_OK] = "Success",
    [TSM_ERR_INTERNAL_ERROR] = "Internal error",
    [TSM_ERR_PASS_NULL_PARAM] = "Pass null param",
    [TSM_ERR_MALLOC_FAILED] = "Malloc failed",
    [TSM_ERR_OUT_OF_DATA] = "Out of data",
    [TSM_ERR_BUFFER_OVERFLOW] = "Buffer overflow",
    [TSM_ERR_BUFFER_TOO_SMALL] = "Buffer too small",
    [TSM_ERR_UNEXPECTED_ASN1_TAG] = "Unexpected ASN1 tag",
    [TSM_ERR_INVALID_ASN1_LENGTH] = "Invalid ASN1 length",
    [TSM_ERR_INVALID_ASN1_VALUE] = "Invalid ASN1 value",
    [TSM_ERR_WRONG_FINAL_BLOCK_LENGTH] = "Wrong length of final block",
    [TSM_ERR_BAD_DECRYPT] = "Bad decrypt",
    [TSM_ERR_WRONG_CIPH_MODE] = "Wrong cipher mode",
    [TSM_ERR_INVALID_HEX_STR] = "Invalid hex string",
    [TSM_ERR_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH] = "Data length not multiple of block length",
    [TSM_ERR_INVALID_AEAD_TAG_LENGTH] = "Invalid AEAD tag length",
    [TSM_ERR_INVALID_OPERATION] = "Invalid operation",
    [TSM_ERR_INVALID_ASCON_SCHEME] = "Invalid Ascon scheme",
    [TSM_ERR_AEAD_VERIFY_FAILED] = "AEAD verify failed",
};
#endif

const char *tsm_err2str(int err)
{
    if (err == TSM_FAILED)
        return "Failed";

    if (err < TSM_OK)
        return NULL;

#ifdef TSM_ERRSTR
    return errstr[err];
#else
    if (err == TSM_OK)
        return "Success";
    else
        return "Error";
#endif
}
