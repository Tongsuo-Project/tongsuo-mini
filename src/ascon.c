/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <stdint.h>
#include <string.h>
#include <tongsuo/mem.h>
#include <tongsuo/minisuo.h>
#include <tongsuo/ascon.h>
#include "internal/ascon.h"
#include "internal/log.h"
#include "internal/meth.h"

#define ASCON_128_IV         0x80400c0600000000ULL
#define ASCON_128A_IV        0x80800c0800000000ULL
#define ASCON_128_KEYBYTES   TSM_ASCON_AEAD_KEY_LEN
#define ASCON_128A_KEYBYTES  TSM_ASCON_AEAD_KEY_LEN
#define ASCON_128_RATE       8
#define ASCON_128A_RATE      16
#define ASCON_128_PA_ROUNDS  12
#define ASCON_128_PB_ROUNDS  6
#define ASCON_128A_PA_ROUNDS 12
#define ASCON_128A_PB_ROUNDS 8

#define ASCON_HASH_IV        0x400c0000000100ULL
#define ASCON_HASHA_IV       0x400c0400000100ULL
#define ASCON_HASH_RATE      8

#ifdef TSM_LOG
static void dump_state(const char *label, TSM_ASCON_STATE *s)
{
    LOGD("%s:\tx0=%016llu x1=%016llu x2=%016llu x3=%016llu x4=%016llu", label, s->x[0], s->x[1],
         s->x[2], s->x[3], s->x[4]);
}
#else
# define dump_state(...)
#endif

static inline uint64_t padding(int len)
{
    return ((uint64_t)(0x80) << (56 - 8 * (len)));
}

static inline uint64_t load_u64(const uint8_t *buf, int len)
{
    uint64_t u64 = 0;
    int i;
    for (i = 0; i < len; ++i)
        u64 |= (uint64_t)buf[i] << (56 - 8 * i);
    return u64;
}

static inline void store_u64(uint64_t u64, int len, uint8_t *buf)
{
    int i;
    for (i = 0; i < len; ++i)
        buf[i] = (uint8_t)(u64 >> (56 - 8 * i));
}

static inline void clear_u64(uint64_t *u64, int len)
{
    int i;
    for (i = 0; i < len; ++i)
        *u64 &= ~((uint64_t)(0xff) << (56 - 8 * (i)));
}

static inline uint64_t ror_u64(uint64_t x, int n)
{
    return x >> n | x << (-n & 63);
}

static inline void permutation(TSM_ASCON_STATE *s, int i)
{
    uint8_t Cr[12] = {0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b};
    uint64_t t0;

    /* addition of round constant */
    s->x[2] ^= Cr[i];

    /* substitution layer */
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];

    t0 = s->x[0] & (~s->x[4]);
    s->x[0] ^= s->x[2] & (~s->x[1]);
    s->x[2] ^= s->x[4] & (~s->x[3]);
    s->x[4] ^= s->x[1] & (~s->x[0]);
    s->x[1] ^= s->x[3] & (~s->x[2]);
    s->x[3] ^= t0;

    s->x[1] ^= s->x[0];
    s->x[3] ^= s->x[2];
    s->x[0] ^= s->x[4];
    s->x[2] = ~s->x[2];

    /* linear diffusion layer */
    s->x[0] = s->x[0] ^ ror_u64(s->x[0], 19) ^ ror_u64(s->x[0], 28);
    s->x[1] = s->x[1] ^ ror_u64(s->x[1], 61) ^ ror_u64(s->x[1], 39);
    s->x[2] = s->x[2] ^ ror_u64(s->x[2], 1) ^ ror_u64(s->x[2], 6);
    s->x[3] = s->x[3] ^ ror_u64(s->x[3], 10) ^ ror_u64(s->x[3], 17);
    s->x[4] = s->x[4] ^ ror_u64(s->x[4], 7) ^ ror_u64(s->x[4], 41);
    dump_state("permutation", s);
}

static inline void P12(TSM_ASCON_STATE *s)
{
    permutation(s, 0);
    permutation(s, 1);
    permutation(s, 2);
    permutation(s, 3);
    permutation(s, 4);
    permutation(s, 5);
    permutation(s, 6);
    permutation(s, 7);
    permutation(s, 8);
    permutation(s, 9);
    permutation(s, 10);
    permutation(s, 11);
}

static inline void P8(TSM_ASCON_STATE *s)
{
    permutation(s, 4);
    permutation(s, 5);
    permutation(s, 6);
    permutation(s, 7);
    permutation(s, 8);
    permutation(s, 9);
    permutation(s, 10);
    permutation(s, 11);
}

static inline void P6(TSM_ASCON_STATE *s)
{
    permutation(s, 6);
    permutation(s, 7);
    permutation(s, 8);
    permutation(s, 9);
    permutation(s, 10);
    permutation(s, 11);
}

int tsm_ascon_aead_update(void *ctx, const unsigned char *in, size_t inl, unsigned char *out,
                          size_t *outl)
{
    if (ctx == NULL)
        return eLOG(TSM_ERR_PASS_NULL_PARAM);

    TSM_ASCON_AEAD_CTX *c = ctx;

    if (outl != NULL)
        *outl = 0;

    /* Processing associated data  */
    if (out == NULL) {
        if (in != NULL && inl > 0) {
            c->phase = ASCON_PHASE_AD;

            if (c->buf_len > 0) {
                if (c->buf_len + inl < c->block_size) {
                    memcpy(c->buf + c->buf_len, in, inl);
                    c->buf_len += inl;
                    return TSM_OK;
                } else {
                    memcpy(c->buf + c->buf_len, in, c->block_size - c->buf_len);
                    in += c->block_size - c->buf_len;
                    inl -= c->block_size - c->buf_len;
                    if (c->mode == TSM_ASCON_AEAD_128) {
                        c->s.x[0] ^= load_u64(c->buf, 8);
                        P6(&c->s);
                    } else {
                        c->s.x[0] ^= load_u64(c->buf, 8);
                        c->s.x[1] ^= load_u64(c->buf + 8, 8);
                        P8(&c->s);
                    }
                    c->buf_len = 0;
                }
            }

            while (inl >= c->block_size) {
                if (c->mode == TSM_ASCON_AEAD_128) {
                    c->s.x[0] ^= load_u64(in, 8);
                    dump_state("absorb adata", &c->s);
                    P6(&c->s);
                } else {
                    c->s.x[0] ^= load_u64(in, 8);
                    c->s.x[1] ^= load_u64(in + 8, 8);
                    dump_state("absorb adata", &c->s);
                    P8(&c->s);
                }

                in += c->block_size;
                inl -= c->block_size;
            }

            memcpy(c->buf, in, inl);
            c->buf_len = inl;
        }

        return TSM_OK;
    }

    if (c->phase == ASCON_PHASE_INIT) {
        /* no ad */
        c->s.x[4] ^= 1;
        c->phase = ASCON_PHASE_TEXT;
    }

    if (c->phase == ASCON_PHASE_AD) {
        /* final associated data block */
        if (c->buf_len >= 8) {
            c->s.x[0] ^= load_u64(c->buf, 8);
            c->s.x[1] ^= load_u64(c->buf + 8, c->buf_len - 8);
            c->s.x[1] ^= padding(c->buf_len - 8);
        } else {
            c->s.x[0] ^= load_u64(c->buf, c->buf_len);
            c->s.x[0] ^= padding(c->buf_len);
        }

        dump_state("pad adata", &c->s);
        c->buf_len = 0;

        if (c->mode == TSM_ASCON_AEAD_128)
            P6(&c->s);
        else
            P8(&c->s);

        c->s.x[4] ^= 1;
        dump_state("domain separation", &c->s);
        c->phase = ASCON_PHASE_TEXT;
    }

    if (in == NULL || inl == 0) {
        return TSM_OK;
    }

    if (c->buf_len > 0) {
        if (c->buf_len + inl < c->block_size) {
            memcpy(c->buf + c->buf_len, in, inl);
            c->buf_len += inl;
            return TSM_OK;
        } else {
            memcpy(c->buf + c->buf_len, in, c->block_size - c->buf_len);
            in += c->block_size - c->buf_len;
            inl -= c->block_size - c->buf_len;
            if (c->mode == TSM_ASCON_AEAD_128) {
                c->s.x[0] ^= load_u64(c->buf, 8);
                store_u64(c->s.x[0], 8, out);
                P6(&c->s);
            } else {
                c->s.x[0] ^= load_u64(c->buf, 8);
                c->s.x[1] ^= load_u64(c->buf + 8, 8);
                store_u64(c->s.x[0], 8, out);
                store_u64(c->s.x[1], 8, out + 8);
                P8(&c->s);
            }
            c->buf_len = 0;
            out += c->block_size;
            *outl += c->block_size;
        }
    }

    while (inl >= c->block_size) {
        if (c->mode == TSM_ASCON_AEAD_128) {
            uint64_t c0 = load_u64(in, 8);
            c->s.x[0] ^= c0;
            store_u64(c->s.x[0], 8, out);

            if (c->flags & TSM_CIPH_FLAG_DECRYPT)
                c->s.x[0] = c0;

            dump_state("absorb text", &c->s);
            P6(&c->s);
        } else {
            uint64_t c0 = load_u64(in, 8);
            uint64_t c1 = load_u64(in + 8, 8);
            c->s.x[0] ^= c0;
            c->s.x[1] ^= c1;
            store_u64(c->s.x[0], 8, out);
            store_u64(c->s.x[1], 8, out + 8);

            if (c->flags & TSM_CIPH_FLAG_DECRYPT) {
                c->s.x[0] = c0;
                c->s.x[1] = c1;
            }

            dump_state("absorb text", &c->s);
            P8(&c->s);
        }

        in += c->block_size;
        inl -= c->block_size;
        out += c->block_size;
        *outl += c->block_size;
    }

    memcpy(c->buf, in, inl);
    c->buf_len = inl;

    return TSM_OK;
}

int tsm_ascon_aead_final(void *ctx, unsigned char *out, size_t *outl)
{
    TSM_ASCON_AEAD_CTX *c = ctx;

    if (c->phase == ASCON_PHASE_INIT) {
        /* no ad and no in text */
        c->s.x[4] ^= 1;
    }

    if (c->phase == ASCON_PHASE_AD) {
        /* final associated data block */
        if (c->buf_len >= 8) {
            c->s.x[0] ^= load_u64(c->buf, 8);
            c->s.x[1] ^= load_u64(c->buf + 8, c->buf_len - 8);
            c->s.x[1] ^= padding(c->buf_len - 8);
        } else {
            c->s.x[0] ^= load_u64(c->buf, c->buf_len);
            c->s.x[0] ^= padding(c->buf_len);
        }

        c->buf_len = 0;

        if (c->mode == TSM_ASCON_AEAD_128)
            P6(&c->s);
        else
            P8(&c->s);

        c->s.x[4] ^= 1;
        c->phase = ASCON_PHASE_TEXT;
    }

    /* final plaintext or ciphertext block */
    if (c->buf_len >= 8) {
        if (c->flags & TSM_CIPH_FLAG_ENCRYPT) {
            c->s.x[0] ^= load_u64(c->buf, 8);
            c->s.x[1] ^= load_u64(c->buf + 8, c->buf_len - 8);
            store_u64(c->s.x[0], 8, out);
            store_u64(c->s.x[1], c->buf_len - 8, out + 8);
        } else {
            uint64_t c0 = load_u64(c->buf, 8);
            uint64_t c1 = load_u64(c->buf + 8, c->buf_len - 8);
            store_u64(c->s.x[0] ^ c0, 8, out);
            store_u64(c->s.x[1] ^ c1, c->buf_len - 8, out + 8);
            c->s.x[0] = c0;
            clear_u64(&c->s.x[1], c->buf_len - 8);
            c->s.x[1] |= c1;
        }

        c->s.x[1] ^= padding(c->buf_len - 8);
    } else {
        if (c->flags & TSM_CIPH_FLAG_ENCRYPT) {
            c->s.x[0] ^= load_u64(c->buf, c->buf_len);
            store_u64(c->s.x[0], c->buf_len, out);
        } else {
            uint64_t c0 = load_u64(c->buf, c->buf_len);
            store_u64(c->s.x[0] ^ c0, c->buf_len, out);
            clear_u64(&c->s.x[0], c->buf_len);
            c->s.x[0] |= c0;
        }

        c->s.x[0] ^= padding(c->buf_len);
    }

    dump_state("pad text", &c->s);
    *outl = c->buf_len;

    /* finalize */
    if (c->mode == TSM_ASCON_AEAD_128) {
        c->s.x[1] ^= c->K[0];
        c->s.x[2] ^= c->K[1];
    } else { // TSM_ASCON_AEAD_128A
        c->s.x[2] ^= c->K[0];
        c->s.x[3] ^= c->K[1];
    }

    dump_state("Finalization 1st key xor", &c->s);
    P12(&c->s);
    c->s.x[3] ^= c->K[0];
    c->s.x[4] ^= c->K[1];
    dump_state("Finalization 2nd key xor", &c->s);
    c->phase = ASCON_PHASE_FINAL;

    /* set tag */
    if (c->flags & TSM_CIPH_FLAG_ENCRYPT) {
        store_u64(c->s.x[3], 8, c->tag);
        store_u64(c->s.x[4], 8, c->tag + 8);
    } else {
        uint8_t t[16];
        store_u64(c->s.x[3], 8, t);
        store_u64(c->s.x[4], 8, t + 8);

        /* verify tag (constant time) */
        int i, result = 0;
        for (i = 0; i < 16; ++i)
            result |= c->tag[i] ^ t[i];

        result = (((result - 1) >> 8) & 1) - 1;
        if (result != 0)
            return eLOG(TSM_ERR_AEAD_VERIFY_FAILED);
    }

    return TSM_OK;
}

void *tsm_ascon_aead_ctx_new(void)
{
    TSM_ASCON_AEAD_CTX *ctx = tsm_calloc(sizeof(TSM_ASCON_AEAD_CTX));

    if (ctx == NULL) {
        LOGE(tsm_err2str(TSM_ERR_MALLOC_FAILED));
        return NULL;
    }

    return ctx;
}

int tsm_ascon_aead_init(void *c, int type, const unsigned char *key, const unsigned char *iv,
                        int flags)
{
    TSM_ASCON_AEAD_CTX *ctx = c;

    if (ctx == NULL || key == NULL || iv == NULL)
        return eLOG(TSM_ERR_PASS_NULL_PARAM);

    ctx->mode = type;
    ctx->flags = flags;

    /* load key and nonce */
    ctx->K[0] = load_u64(key, 8);
    ctx->K[1] = load_u64(key + 8, 8);
    ctx->N[0] = load_u64(iv, 8);
    ctx->N[1] = load_u64(iv + 8, 8);

    if (ctx->mode == TSM_ASCON_AEAD_128) {
        ctx->block_size = ASCON_128_RATE;
        ctx->a = ASCON_128_PA_ROUNDS;
        ctx->b = ASCON_128_PB_ROUNDS;
        ctx->s.x[0] = ASCON_128_IV;
    } else if (ctx->mode == TSM_ASCON_AEAD_128A) {
        ctx->block_size = ASCON_128A_RATE;
        ctx->a = ASCON_128A_PA_ROUNDS;
        ctx->b = ASCON_128A_PB_ROUNDS;
        ctx->s.x[0] = ASCON_128A_IV;
    } else {
        return eLOG(TSM_ERR_INVALID_ASCON_SCHEME);
    }

    ctx->s.x[1] = ctx->K[0];
    ctx->s.x[2] = ctx->K[1];
    ctx->s.x[3] = ctx->N[0];
    ctx->s.x[4] = ctx->N[1];
    dump_state("Initialiation 1st initial state", &ctx->s);
    P12(&ctx->s);
    ctx->s.x[3] ^= ctx->K[0];
    ctx->s.x[4] ^= ctx->K[1];
    dump_state("Initialiation 2nd key xor", &ctx->s);
    ctx->phase = ASCON_PHASE_INIT;
    return TSM_OK;
}

void tsm_ascon_aead_ctx_free(void *ctx)
{
    if (ctx != NULL) {
        TSM_ASCON_AEAD_CTX *c = (TSM_ASCON_AEAD_CTX *)ctx;
        tsm_memzero(c, sizeof(*c));
        tsm_free(c);
    }
}

int tsm_ascon_aead_set_tag(void *ctx, const unsigned char *tag)
{
    if (ctx == NULL || tag == NULL)
        return eLOG(TSM_ERR_PASS_NULL_PARAM);

    TSM_ASCON_AEAD_CTX *c = (TSM_ASCON_AEAD_CTX *)ctx;

    if (c->flags & TSM_CIPH_FLAG_ENCRYPT) {
        return eLOG(TSM_ERR_INVALID_OPERATION);
    } else {
        memcpy(c->tag, tag, sizeof(c->tag));
    }

    return TSM_OK;
}

int tsm_ascon_aead_get_tag(void *ctx, unsigned char *tag)
{
    if (ctx == NULL || tag == NULL)
        return eLOG(TSM_ERR_PASS_NULL_PARAM);

    TSM_ASCON_AEAD_CTX *c = (TSM_ASCON_AEAD_CTX *)ctx;

    if (c->flags & TSM_CIPH_FLAG_ENCRYPT) {
        memcpy(tag, c->tag, sizeof(c->tag));
    } else {
        return eLOG(TSM_ERR_INVALID_OPERATION);
    }

    return TSM_OK;
}

int tsm_ascon_aead_oneshot(int type, const unsigned char *key, const unsigned char *iv,
                           const unsigned char *ad, size_t adl, const unsigned char *in, size_t inl,
                           unsigned char *out, size_t *outl, int flags)
{
    size_t tmplen = 0;
    int ret;
    void *ctx;

    if (key == NULL || iv == NULL || out == NULL || outl == NULL)
        return eLOG(TSM_ERR_PASS_NULL_PARAM);

    ctx = tsm_ascon_aead_ctx_new();
    if (ctx == NULL)
        return TSM_ERR_MALLOC_FAILED;

    if ((ret = tsm_ascon_aead_init(ctx, type, key, iv, flags)) != TSM_OK)
        goto err;

    /* Expect tag after plaintext */
    if (flags & TSM_CIPH_FLAG_DECRYPT) {
        if ((ret = tsm_ascon_aead_set_tag(ctx, in + inl - TSM_ASCON_AEAD_TAG_LEN)) != TSM_OK)
            goto err;

        inl -= TSM_ASCON_AEAD_TAG_LEN;
    }

    if (ad != NULL && adl > 0) {
        if ((ret = tsm_ascon_aead_update(ctx, ad, adl, NULL, NULL)) != TSM_OK)
            goto err;
    }

    if (in != NULL && inl > 0) {
        if ((ret = tsm_ascon_aead_update(ctx, in, inl, out, &tmplen)) != TSM_OK)
            goto err;
    }

    if ((ret = tsm_ascon_aead_final(ctx, out + tmplen, outl)) != TSM_OK)
        goto err;

    *outl += tmplen;

    /* Append tag to ciphertext */
    if (flags & TSM_CIPH_FLAG_ENCRYPT) {
        if ((ret = tsm_ascon_aead_get_tag(ctx, out + *outl)) != TSM_OK)
            goto err;

        *outl += TSM_ASCON_AEAD_TAG_LEN;
    }

    tsm_ascon_aead_ctx_free(ctx);
    return TSM_OK;
err:
    tsm_ascon_aead_ctx_free(ctx);
    return ret;
}

static int ascon_hash_init(void *c, int alg)
{
    TSM_ASCON_HASH_CTX *ctx = (TSM_ASCON_HASH_CTX *)c;

    tsm_memzero(ctx, sizeof(*ctx));

    ctx->alg = alg;

    if (ctx->alg == TSM_HASH_ASCON_HASH) {
        ctx->s.x[0] = ASCON_HASH_IV;
    } else if (ctx->alg == TSM_HASH_ASCON_HASHA) {
        ctx->s.x[0] = ASCON_HASHA_IV;
    } else {
        return eLOG(TSM_ERR_INVALID_HASH_ALGORITHM);
    }

    P12(&ctx->s);
    dump_state("Initialization", &ctx->s);

    return 0;
}

int tsm_ascon_hash_init(void *c)
{
    return ascon_hash_init(c, TSM_HASH_ASCON_HASH);
}

int tsm_ascon_hasha_init(void *c)
{
    return ascon_hash_init(c, TSM_HASH_ASCON_HASHA);
}

static int ascon_hash_update(void *ctx, const unsigned char *in, size_t inl)
{
    TSM_ASCON_HASH_CTX *c = ctx;

    if (ctx == NULL)
        return eLOG(TSM_ERR_PASS_NULL_PARAM);

    if (in == NULL || inl == 0)
        return TSM_OK;

    if (c->buf_len > 0) {
        if (c->buf_len + inl < ASCON_HASH_RATE) {
            memcpy(c->buf + c->buf_len, in, inl);
            c->buf_len += inl;
            return TSM_OK;
        } else {
            memcpy(c->buf + c->buf_len, in, ASCON_HASH_RATE - c->buf_len);
            c->s.x[0] ^= load_u64(c->buf, 8);
            dump_state("absorb text", &c->s);

            if (c->alg == TSM_HASH_ASCON_HASH)
                P12(&c->s);
            else
                P8(&c->s);

            in += ASCON_HASH_RATE - c->buf_len;
            inl -= ASCON_HASH_RATE - c->buf_len;
            c->buf_len = 0;
        }
    }

    while (inl >= ASCON_HASH_RATE) {
        c->s.x[0] ^= load_u64(in, 8);
        dump_state("absorb text", &c->s);

        if (c->alg == TSM_HASH_ASCON_HASH)
            P12(&c->s);
        else
            P8(&c->s);

        in += ASCON_HASH_RATE - c->buf_len;
        inl -= ASCON_HASH_RATE - c->buf_len;
    }

    memcpy(c->buf, in, inl);
    c->buf_len = inl;

    return TSM_OK;
}

int tsm_ascon_hash_update(void *ctx, const unsigned char *in, size_t inl)
{
    return ascon_hash_update(ctx, in, inl);
}

int tsm_ascon_hasha_update(void *ctx, const unsigned char *in, size_t inl)
{
    return ascon_hash_update(ctx, in, inl);
}

int ascon_hash_final(void *ctx, unsigned char *out, size_t *outl)
{
    TSM_ASCON_HASH_CTX *c = ctx;
    int len;

    if (ctx == NULL || out == NULL || outl == NULL)
        return eLOG(TSM_ERR_PASS_NULL_PARAM);

    c->s.x[0] ^= load_u64(c->buf, c->buf_len);
    c->s.x[0] ^= padding(c->buf_len);

    dump_state("pad text", &c->s);
    P12(&c->s);

    *outl = 0;

    len = TSM_ASCON_HASH_LEN;
    while (len > ASCON_HASH_RATE) {
        store_u64(c->s.x[0], 8, out);
        dump_state("Squeeze output", &c->s);

        if (c->alg == TSM_HASH_ASCON_HASH)
            P12(&c->s);
        else
            P8(&c->s);

        out += ASCON_HASH_RATE;
        *outl += ASCON_HASH_RATE;
        len -= ASCON_HASH_RATE;
    }
    /* squeeze final output block */
    store_u64(c->s.x[0], len, out);
    *outl += len;
    dump_state("Squeeze output", &c->s);

    return TSM_OK;
}

int tsm_ascon_hash_final(void *ctx, unsigned char *out, size_t *outl)
{
    return ascon_hash_final(ctx, out, outl);
}

int tsm_ascon_hasha_final(void *ctx, unsigned char *out, size_t *outl)
{
    return ascon_hash_final(ctx, out, outl);
}

int tsm_ascon_hash_oneshot(int hash, const unsigned char *in, size_t inl, unsigned char *out,
                           size_t *outl)
{
    int ret;
    TSM_ASCON_HASH_CTX *ctx = tsm_ascon_hash_ctx_new();
    if (ctx == NULL)
        return eLOG(TSM_ERR_MALLOC_FAILED);

    if ((ret = ascon_hash_init(ctx, hash)) != TSM_OK
        || (ret = ascon_hash_update(ctx, in, inl)) != TSM_OK
        || (ret = ascon_hash_final(ctx, out, outl)) != TSM_OK) {
        tsm_ascon_hash_ctx_free(ctx);
        return ret;
    }

    tsm_ascon_hash_ctx_free(ctx);
    return TSM_OK;
}

void *tsm_ascon_hash_ctx_new(void)
{
    TSM_ASCON_HASH_CTX *ctx = tsm_alloc(sizeof(TSM_ASCON_HASH_CTX));
    if (ctx == NULL) {
        LOGERR(TSM_ERR_MALLOC_FAILED);
        return NULL;
    }

    return ctx;
}

void tsm_ascon_hash_ctx_free(void *ctx)
{
    if (ctx != NULL) {
        TSM_ASCON_HASH_CTX *c = (TSM_ASCON_HASH_CTX *)ctx;
        tsm_memzero(c, sizeof(*c));
        tsm_free(c);
    }
}
