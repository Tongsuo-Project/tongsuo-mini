/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <tongsuo/minisuo.h>
#include <tongsuo/ascon.h>
#include <tongsuo/sm3.h>
#include "internal/sm3.h"
#include "internal/meth.h"

#ifdef TSM_HAVE_ASCON
static TSM_HASH_METH tsm_ascon_hash_meth = {
    .name = "ascon_hash",
    .alg = TSM_HASH_ASCON_HASH,
    .hashsize = TSM_ASCON_HASH_LEN,
    /* The ASCON-HASH block absorption rate of 8 bytes is too short so we use the HMAC-SHA-256
    block size of 64 instead. */
    .blocksize = 64,
    .newctx = tsm_ascon_hash_ctx_new,
    .freectx = tsm_ascon_hash_ctx_free,
    .init = tsm_ascon_hash_init,
    .update = tsm_ascon_hash_update,
    .final = tsm_ascon_hash_final,
};

static TSM_HASH_METH tsm_ascon_hasha_meth = {
    .name = "ascon_hasha",
    .alg = TSM_HASH_ASCON_HASHA,
    .hashsize = TSM_ASCON_HASH_LEN,
    /* The ASCON-HASHA block absorption rate of 8 bytes is too short so we use the HMAC-SHA-256
    block size of 64 instead.*/
    .blocksize = 64,
    .newctx = tsm_ascon_hash_ctx_new,
    .freectx = tsm_ascon_hash_ctx_free,
    .init = tsm_ascon_hasha_init,
    .update = tsm_ascon_hasha_update,
    .final = tsm_ascon_hasha_final,
};
#endif

#ifdef TSM_HAVE_SM3
static TSM_HASH_METH tsm_sm3_meth = {
    .name = "sm3",
    .alg = TSM_HASH_SM3,
    .hashsize = TSM_SM3_DIGEST_LEN,
    .blocksize = TSM_SM3_CBLOCK,
    .newctx = tsm_sm3_ctx_new,
    .freectx = tsm_sm3_ctx_free,
    .init = tsm_sm3_init,
    .update = tsm_sm3_update,
    .final = tsm_sm3_final,
};
#endif

void *tsm_get_hash_meth(int alg)
{
#ifdef TSM_HAVE_SM3
    if (alg == TSM_HASH_SM3)
        return &tsm_sm3_meth;
#endif

#ifdef TSM_HAVE_ASCON
    if (alg == TSM_HASH_ASCON_HASH)
        return &tsm_ascon_hash_meth;

    if (alg == TSM_HASH_ASCON_HASHA)
        return &tsm_ascon_hasha_meth;
#endif

    return NULL;
}
