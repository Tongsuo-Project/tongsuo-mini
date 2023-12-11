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
#define HMAC_BLOCK_SIZE 64

typedef struct {
    void *algctx;
    TSM_HASH_METH *meth;
    const unsigned char *key;
    size_t keylen;
} TSM_HMAC_CTX;

static void hmac_xor_pad(unsigned char *out, const unsigned char *in, size_t size,
                         unsigned char pad)
{
    while (size > 0) {
        *out++ = *in++ ^ pad;
        --size;
    }
}

void *tsm_hmac_ctx_new(void)
{
    return tsm_calloc(sizeof(TSM_HMAC_CTX));
}

void tsm_hmac_ctx_free(void *ctx)
{
    if (ctx == NULL)
        return;

    tsm_free(ctx);
}

static int hmac_absorb_key(TSM_HMAC_CTX *ctx, const unsigned char *key, size_t keylen,
                           unsigned char pad)
{
    unsigned char *temp = NULL;
    size_t temp_len;
    int ret = TSM_FAILED;
    size_t posn, len;

    temp = tsm_alloc(ctx->meth->hashsize);
    if (temp == NULL)
        return eLOG(TSM_ERR_MALLOC_FAILED);

    /* Break the key up into smaller chunks and XOR it with "pad".
     * We do it this way to avoid having a large buffer on the
     * stack of size HMAC_BLOCK_SIZE. */
    if (keylen <= HMAC_BLOCK_SIZE) {
        posn = 0;
        while (posn < keylen) {
            len = keylen - posn;
            if (len > ctx->meth->hashsize)
                len = ctx->meth->hashsize;
            hmac_xor_pad(temp, key + posn, len, pad);
            if ((ret = ctx->meth->update(ctx->algctx, temp, len)) != TSM_OK)
                goto err;
            posn += len;
        }
    } else {
        /* Hash long keys down first and then absorb */
        if ((ret = ctx->meth->update(ctx->algctx, key, keylen)) != TSM_OK
            || (ret = ctx->meth->final(ctx->algctx, temp, &temp_len)) != TSM_OK)
            goto err;

        if (temp_len != ctx->meth->hashsize) {
            ret = TSM_ERR_INVALID_HASH_SIZE;
            goto err;
        }

        if ((ret = ctx->meth->init(ctx->algctx, ctx->meth->type)) != TSM_OK)
            goto err;
        hmac_xor_pad(temp, temp, temp_len, pad);
        if ((ret = ctx->meth->update(ctx->algctx, temp, temp_len)) != TSM_OK)
            goto err;
        posn = temp_len;
    }

    /* Pad the rest of the block with the padding value */
    memset(temp, pad, ctx->meth->hashsize);
    while (posn < HMAC_BLOCK_SIZE) {
        len = HMAC_BLOCK_SIZE - posn;
        if (len > ctx->meth->hashsize)
            len = ctx->meth->hashsize;
        if ((ret = ctx->meth->update(ctx->algctx, temp, len)) != TSM_OK)
            goto err;
        posn += len;
    }

    ret = TSM_OK;
err:
    tsm_free(temp);
    return ret;
}

int tsm_hmac_init(void *ctx, const unsigned char *key, size_t keylen, void *meth)
{
    TSM_HMAC_CTX *c = (TSM_HMAC_CTX *)ctx;
    int ret;

    c->key = key;
    c->keylen = keylen;
    c->meth = meth;

    if (c->algctx == NULL) {
        c->algctx = c->meth->newctx();
        if (c->algctx == NULL)
            return eLOG(TSM_ERR_MALLOC_FAILED);
    }

    if ((ret = c->meth->init(c->algctx, c->meth->type)) != TSM_OK
        || (ret = hmac_absorb_key(c, key, keylen, HMAC_IPAD)) != TSM_OK)
        return ret;

    return TSM_OK;
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
    size_t temp_len;
    int ret;

    temp = tsm_alloc(c->meth->hashsize);
    if (temp == NULL)
        return eLOG(TSM_ERR_MALLOC_FAILED);

    if ((ret = c->meth->final(c->algctx, temp, &temp_len)) != TSM_OK
        || temp_len != c->meth->hashsize
        || (ret = c->meth->init(c->algctx, c->meth->type)) != TSM_OK
        || (ret = hmac_absorb_key(c, c->key, c->keylen, HMAC_OPAD)) != TSM_OK
        || (ret = c->meth->update(c->algctx, temp, temp_len)) != TSM_OK
        || (ret = c->meth->final(c->algctx, out, outl)) != TSM_OK) {
        tsm_free(temp);
        return ret;
    }

    tsm_free(temp);
    return TSM_OK;
}

int tsm_hmac_oneshot(void *meth, const unsigned char *key, size_t keylen, const unsigned char *in,
                     size_t inlen, unsigned char *out, size_t *outl)
{
    TSM_HMAC_CTX *ctx;
    int ret;

    ctx = tsm_hmac_ctx_new();
    if (ctx == NULL)
        return eLOG(TSM_ERR_MALLOC_FAILED);

    if ((ret = tsm_hmac_init(ctx, key, keylen, meth)) != TSM_OK
        || (ret = tsm_hmac_update(ctx, in, inlen)) != TSM_OK
        || (ret = tsm_hmac_final(ctx, out, outl)) != TSM_OK) {
        tsm_hmac_ctx_free(ctx);
        return ret;
    }

    tsm_hmac_ctx_free(ctx);
    return TSM_OK;
}
