/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include "internal/log.h"
#include "internal/meth.h"
#include <tongsuo/mem.h>
#include <tongsuo/hmac.h>
#include <tongsuo/oscore_cose.h>
#include <tongsuo/ascon.h>
#include <string.h>
#include <stdio.h>

static int oscore_hmac_hash(cose_hmac_alg_t hmac_alg, TSM_STR *key, TSM_STR *data, TSM_STR **hmac)
{
    int ret;
    unsigned char *out = NULL;
    size_t outl;
    TSM_HASH_METH *meth = tsm_ascon_hash_meth(hmac_alg);

    if (meth == NULL)
        return eLOG(TSM_ERR_INVALID_ALGORITHM);

    out = tsm_alloc(meth->hashsize);
    if (out == NULL)
        return eLOG(TSM_ERR_MALLOC_FAILED);

    if ((ret = tsm_hmac_oneshot(meth, key->s, key->length, data->s, data->length, out, &outl))
        != TSM_OK) {
        tsm_free(out);
        LOGE("oscore_hmac_hash: Failed hmac\n");
        return ret;
    }

    *hmac = tsm_str_new(out, outl);
    tsm_free(out);

    return TSM_OK;
}

static int
oscore_hkdf_extract(cose_hkdf_alg_t hkdf_alg, TSM_STR *salt, TSM_STR *ikm, TSM_STR **hkdf_extract)
{
    cose_hmac_alg_t hmac_alg;
    int ret;

    assert(ikm);
    if ((ret = tsm_cose_get_hmac_alg_for_hkdf(hkdf_alg, &hmac_alg)) != TSM_OK)
        return ret;
    if (salt == NULL || salt->s == NULL) {
        uint8_t zeroes_data[32];
        TSM_STR zeroes;

        memset(zeroes_data, 0, sizeof(zeroes_data));
        zeroes.s = zeroes_data;
        zeroes.length = sizeof(zeroes_data);

        return oscore_hmac_hash(hmac_alg, &zeroes, ikm, hkdf_extract);
    } else {
        return oscore_hmac_hash(hmac_alg, salt, ikm, hkdf_extract);
    }
}

static int oscore_hkdf_expand(cose_hkdf_alg_t hkdf_alg,
                              TSM_STR *prk,
                              uint8_t *info,
                              size_t info_len,
                              uint8_t *okm,
                              size_t okm_len)
{
    int ret;
    size_t N = (okm_len + 32 - 1) / 32; /* ceil(okm_len/32) */
    uint8_t *aggregate_buffer = tsm_alloc(32 + info_len + 1);
    uint8_t *out_buffer = tsm_alloc((N + 1) * 32); /* 32 extra bytes to fit the last block */
    size_t i;
    TSM_STR data;
    TSM_STR *hkdf = NULL;
    cose_hmac_alg_t hmac_alg;

    if ((ret = tsm_cose_get_hmac_alg_for_hkdf(hkdf_alg, &hmac_alg)) != TSM_OK)
        goto fail;
    /* Compose T(1) */
    memcpy(aggregate_buffer, info, info_len);
    aggregate_buffer[info_len] = 0x01;

    data.s = aggregate_buffer;
    data.length = info_len + 1;
    if ((ret = oscore_hmac_hash(hmac_alg, prk, &data, &hkdf)) != TSM_OK)
        goto fail;
    memcpy(&out_buffer[0], hkdf->s, hkdf->length);
    tsm_str_free(hkdf);

    /* Compose T(2) -> T(N) */
    memcpy(aggregate_buffer, &(out_buffer[0]), 32);
    for (i = 1; i < N; i++) {
        memcpy(&(aggregate_buffer[32]), info, info_len);
        aggregate_buffer[32 + info_len] = (uint8_t)(i + 1);
        data.s = aggregate_buffer;
        data.length = 32 + info_len + 1;
        if ((ret = oscore_hmac_hash(hmac_alg, prk, &data, &hkdf)) != TSM_OK)
            goto fail;
        memcpy(&out_buffer[i * 32], hkdf->s, hkdf->length);
        tsm_str_free(hkdf);
        memcpy(aggregate_buffer, &(out_buffer[i * 32]), 32);
    }
    memcpy(okm, out_buffer, okm_len);
    tsm_free(out_buffer);
    tsm_free(aggregate_buffer);
    return TSM_OK;

fail:
    tsm_free(out_buffer);
    tsm_free(aggregate_buffer);
    return ret;
}

int oscore_hkdf(cose_hkdf_alg_t hkdf_alg,
                TSM_STR *salt,
                TSM_STR *ikm,
                uint8_t *info,
                size_t info_len,
                uint8_t *okm,
                size_t okm_len)
{
    int ret;
    TSM_STR *hkdf_extract = NULL;
    if ((ret = oscore_hkdf_extract(hkdf_alg, salt, ikm, &hkdf_extract)) != TSM_OK)
        return ret;
    ret = oscore_hkdf_expand(hkdf_alg, hkdf_extract, info, info_len, okm, okm_len);
    tsm_str_free(hkdf_extract);
    return ret;
}
