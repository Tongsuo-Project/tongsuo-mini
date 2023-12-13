/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include "internal/meth.h"
#include "internal/log.h"
#include <tongsuo/minisuo.h>
#include <tongsuo/hmac.h>
#include <tongsuo/mem.h>
#include <string.h>

#define HMAC_IPAD       0x36
#define HMAC_OPAD       0x5C

/* The current largest case is for SHA3-224 */
#define HMAC_MAX_MD_CBLOCK_SIZE 144

typedef struct {
    void *algctx;
    TSM_HASH_METH *meth;
    unsigned char *key;
    size_t keylen;
} TSM_HMAC_CTX;

void *tsm_hmac_ctx_new(void)
{
    return tsm_calloc(sizeof(TSM_HMAC_CTX));
}

void tsm_hmac_ctx_free(void *ctx)
{
    if (ctx == NULL)
        return;

    TSM_HMAC_CTX *c = (TSM_HMAC_CTX *)ctx;
    if (c->algctx != NULL) {
        c->meth->freectx(c->algctx);
        c->algctx = NULL;
    }

    tsm_free(c->key);
    tsm_free(c);
}

int tsm_hmac_init(void *ctx, const unsigned char *key, size_t keylen, int hash_alg)
{
    TSM_HMAC_CTX *c = (TSM_HMAC_CTX *)ctx;
    void *meth = tsm_get_hash_meth(hash_alg);
    unsigned char *temp = NULL;
    unsigned char pad[HMAC_MAX_MD_CBLOCK_SIZE];
    size_t temp_len;
    int ret, i;

    if (meth == NULL)
        return eLOG(TSM_ERR_INVALID_HASH_ALGORITHM);

    c->meth = meth;

    if (c->algctx == NULL) {
        c->algctx = c->meth->newctx();
        if (c->algctx == NULL)
            return eLOG(TSM_ERR_MALLOC_FAILED);
    }

    temp = tsm_alloc(c->meth->blocksize);
    if (temp == NULL)
        return eLOG(TSM_ERR_MALLOC_FAILED);

    if (keylen > c->meth->blocksize) {
        if (c->meth->blocksize < c->meth->hashsize) {
            ret = TSM_ERR_INVALID_HASH_SIZE;
            goto err;
        }

        if ((ret = c->meth->init(c->algctx)) != TSM_OK
            || (ret = c->meth->update(c->algctx, key, keylen)) != TSM_OK
            || (ret = c->meth->final(c->algctx, temp, &temp_len)) != TSM_OK)
            goto err;
    } else {
        memcpy(temp, key, keylen);
        temp_len = keylen;
    }

    c->key = temp;
    c->keylen = temp_len;
    temp = NULL;

    if (c->keylen < c->meth->blocksize)
        memset(c->key + c->keylen, 0, c->meth->blocksize - c->keylen);

    for (i = 0; i < c->meth->blocksize; i++)
        pad[i] = c->key[i] ^ HMAC_IPAD;

    if ((ret = c->meth->init(c->algctx)) != TSM_OK
        || (ret = c->meth->update(c->algctx, pad, c->meth->blocksize)) != TSM_OK)
        goto err;

    ret = TSM_OK;
err:
    tsm_free(temp);
    return ret;
}

int tsm_hmac_update(void *ctx, const unsigned char *in, size_t inlen)
{
    TSM_HMAC_CTX *c = (TSM_HMAC_CTX *)ctx;
    int ret;

    if ((ret = c->meth->update(c->algctx, in, inlen)) != TSM_OK)
        return ret;

    return TSM_OK;
}

int tsm_hmac_final(void *ctx, unsigned char *out, size_t *outl)
{
    TSM_HMAC_CTX *c = (TSM_HMAC_CTX *)ctx;
    unsigned char *temp = NULL;
    unsigned char pad[HMAC_MAX_MD_CBLOCK_SIZE];
    size_t temp_len;
    int ret, i;

    temp = tsm_alloc(c->meth->hashsize);
    if (temp == NULL)
        return eLOG(TSM_ERR_MALLOC_FAILED);

    if ((ret = c->meth->final(c->algctx, temp, &temp_len)) != TSM_OK)
        goto err;

    for (i = 0; i < c->meth->blocksize; i++)
        pad[i] = c->key[i] ^ HMAC_OPAD;

    if ((ret = c->meth->init(c->algctx) != TSM_OK)
        || (ret = c->meth->update(c->algctx, pad, c->meth->blocksize)) != TSM_OK
        || (ret = c->meth->update(c->algctx, temp, temp_len)) != TSM_OK
        || (ret = c->meth->final(c->algctx, out, outl)) != TSM_OK) {
        goto err;
    }

    ret = TSM_OK;
err:
    tsm_free(temp);
    return ret;
}

int tsm_hmac_oneshot(int hash_alg, const unsigned char *key, size_t keylen, const unsigned char *in,
                     size_t inlen, unsigned char *out, size_t *outl)
{
    TSM_HMAC_CTX *ctx;
    int ret;

    ctx = tsm_hmac_ctx_new();
    if (ctx == NULL)
        return eLOG(TSM_ERR_MALLOC_FAILED);

    if ((ret = tsm_hmac_init(ctx, key, keylen, hash_alg)) != TSM_OK
        || (ret = tsm_hmac_update(ctx, in, inlen)) != TSM_OK
        || (ret = tsm_hmac_final(ctx, out, outl)) != TSM_OK) {
        tsm_hmac_ctx_free(ctx);
        return ret;
    }

    tsm_hmac_ctx_free(ctx);
    return TSM_OK;
}
