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
#include <tongsuo/minisuo.h>
#include "internal/ascon.h"
#include "internal/log.h"
#include "internal/mem.h"

#define CRYPTO_VERSION       "1.2.7"
#define CRYPTO_KEYBYTES      16
#define CRYPTO_NSECBYTES     0
#define CRYPTO_NPUBBYTES     16
#define CRYPTO_ABYTES        16
#define CRYPTO_NOOVERLAP     1
#define ASCON_AEAD_RATE      8

#define ASCON_128_KEYBYTES   16
#define ASCON_128A_KEYBYTES  16
#define ASCON_128_RATE       8
#define ASCON_128A_RATE      16
#define ASCON_128_PA_ROUNDS  12
#define ASCON_128_PB_ROUNDS  6
#define ASCON_128A_PA_ROUNDS 12
#define ASCON_128A_PB_ROUNDS 8

#define ASCON_128_IV                                                                               \
 (((uint64_t)(ASCON_128_KEYBYTES * 8) << 56) | ((uint64_t)(ASCON_128_RATE * 8) << 48)              \
  | ((uint64_t)(ASCON_128_PA_ROUNDS) << 40) | ((uint64_t)(ASCON_128_PB_ROUNDS) << 32))

#define ASCON_128A_IV                                                                              \
 (((uint64_t)(ASCON_128A_KEYBYTES * 8) << 56) | ((uint64_t)(ASCON_128A_RATE * 8) << 48)            \
  | ((uint64_t)(ASCON_128A_PA_ROUNDS) << 40) | ((uint64_t)(ASCON_128A_PB_ROUNDS) << 32))

/* get byte from 64-bit Ascon word */
#define GETBYTE(x, i) ((uint8_t)((uint64_t)(x) >> (56 - 8 * (i))))

/* set byte in 64-bit Ascon word */
#define SETBYTE(b, i) ((uint64_t)(b) << (56 - 8 * (i)))

/* set padding byte in 64-bit Ascon word */
#define PAD(i) SETBYTE(0x80, i)

static void printstate(const char *label, ascon_state_t *s)
{
    LOGD("%s:\tx0=%016llu x1=%016llu x2=%016llu x3=%016llu x4=%016llu", label, s->x[0], s->x[1],
         s->x[2], s->x[3], s->x[4]);
}

/* load bytes into 64-bit Ascon word */
static inline uint64_t LOADBYTES(const uint8_t *bytes, int n)
{
    int i;
    uint64_t x = 0;
    for (i = 0; i < n; ++i)
        x |= SETBYTE(bytes[i], i);
    return x;
}

/* store bytes from 64-bit Ascon word */
static inline void STOREBYTES(uint8_t *bytes, uint64_t x, int n)
{
    int i;
    for (i = 0; i < n; ++i)
        bytes[i] = GETBYTE(x, i);
}

/* clear bytes in 64-bit Ascon word */
static inline uint64_t CLEARBYTES(uint64_t x, int n)
{
    int i;
    for (i = 0; i < n; ++i)
        x &= ~SETBYTE(0xff, i);
    return x;
}

static inline uint64_t ROR(uint64_t x, int n)
{
    return x >> n | x << (-n & 63);
}

static inline void ROUND(ascon_state_t *s, uint8_t C)
{
    ascon_state_t t;
    /* addition of round constant */
    s->x[2] ^= C;
    /* printstate(" round constant", s); */
    /* substitution layer */
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    /* start of keccak s-box */
    t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
    t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
    t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
    t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
    t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
    /* end of keccak s-box */
    t.x[1] ^= t.x[0];
    t.x[0] ^= t.x[4];
    t.x[3] ^= t.x[2];
    t.x[2] = ~t.x[2];

    /* linear diffusion layer */
    s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
    s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
    s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
    s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
    s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
    printstate("round output", s);
}

static inline void P12(ascon_state_t *s)
{
    ROUND(s, 0xf0);
    ROUND(s, 0xe1);
    ROUND(s, 0xd2);
    ROUND(s, 0xc3);
    ROUND(s, 0xb4);
    ROUND(s, 0xa5);
    ROUND(s, 0x96);
    ROUND(s, 0x87);
    ROUND(s, 0x78);
    ROUND(s, 0x69);
    ROUND(s, 0x5a);
    ROUND(s, 0x4b);
}

static inline void P8(ascon_state_t *s)
{
    ROUND(s, 0xb4);
    ROUND(s, 0xa5);
    ROUND(s, 0x96);
    ROUND(s, 0x87);
    ROUND(s, 0x78);
    ROUND(s, 0x69);
    ROUND(s, 0x5a);
    ROUND(s, 0x4b);
}

static inline void P6(ascon_state_t *s)
{
    ROUND(s, 0x96);
    ROUND(s, 0x87);
    ROUND(s, 0x78);
    ROUND(s, 0x69);
    ROUND(s, 0x5a);
    ROUND(s, 0x4b);
}

int tsm_ascon_aead_update(void *ctx, const unsigned char *in, int inl, unsigned char *out,
                          int *outl)
{
    if (ctx == NULL)
        return ERRLOG(TSM_ERR_PASS_NULL_PARAM);

    TSM_ASCON_CTX *c = ctx;

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
                        c->s.x[0] ^= LOADBYTES(c->buf, 8);
                        P6(&c->s);
                    } else {
                        c->s.x[0] ^= LOADBYTES(c->buf, 8);
                        c->s.x[1] ^= LOADBYTES(c->buf + 8, 8);
                        P8(&c->s);
                    }
                    c->buf_len = 0;
                }
            }

            while (inl >= c->block_size) {
                if (c->mode == TSM_ASCON_AEAD_128) {
                    c->s.x[0] ^= LOADBYTES(in, 8);
                    printstate("absorb adata", &c->s);
                    P6(&c->s);
                } else {
                    c->s.x[0] ^= LOADBYTES(in, 8);
                    c->s.x[1] ^= LOADBYTES(in + 8, 8);
                    printstate("absorb adata", &c->s);
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
            c->s.x[0] ^= LOADBYTES(c->buf, 8);
            c->s.x[1] ^= LOADBYTES(c->buf + 8, c->buf_len - 8);
            c->s.x[1] ^= PAD(c->buf_len - 8);
        } else {
            c->s.x[0] ^= LOADBYTES(c->buf, c->buf_len);
            c->s.x[0] ^= PAD(c->buf_len);
        }

        printstate("pad adata", &c->s);
        c->buf_len = 0;

        if (c->mode == TSM_ASCON_AEAD_128)
            P6(&c->s);
        else
            P8(&c->s);

        c->s.x[4] ^= 1;
        printstate("domain separation", &c->s);
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
                c->s.x[0] ^= LOADBYTES(c->buf, 8);
                STOREBYTES(out, c->s.x[0], 8);
                P6(&c->s);
            } else {
                c->s.x[0] ^= LOADBYTES(c->buf, 8);
                c->s.x[1] ^= LOADBYTES(c->buf + 8, 8);
                STOREBYTES(out, c->s.x[0], 8);
                STOREBYTES(out + 8, c->s.x[1], 8);
                P8(&c->s);
            }
            c->buf_len = 0;
            out += c->block_size;
            *outl += c->block_size;
        }
    }

    while (inl >= c->block_size) {
        if (c->mode == TSM_ASCON_AEAD_128) {
            uint64_t c0 = LOADBYTES(in, 8);
            c->s.x[0] ^= c0;
            STOREBYTES(out, c->s.x[0], 8);

            if (c->flags & TSM_CIPH_FLAG_DECRYPT)
                c->s.x[0] = c0;

            printstate("absorb text", &c->s);
            P6(&c->s);
        } else {
            uint64_t c0 = LOADBYTES(in, 8);
            uint64_t c1 = LOADBYTES(in + 8, 8);
            c->s.x[0] ^= c0;
            c->s.x[1] ^= c1;
            STOREBYTES(out, c->s.x[0], 8);
            STOREBYTES(out + 8, c->s.x[1], 8);

            if (c->flags & TSM_CIPH_FLAG_DECRYPT) {
                c->s.x[0] = c0;
                c->s.x[1] = c1;
            }

            printstate("absorb text", &c->s);
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

int tsm_ascon_aead_final(void *ctx, unsigned char *out, int *outl)
{
    TSM_ASCON_CTX *c = ctx;

    if (c->phase == ASCON_PHASE_INIT) {
        /* no ad and no in text */
        c->s.x[4] ^= 1;
    }

    if (c->phase == ASCON_PHASE_AD) {
        /* final associated data block */
        if (c->buf_len >= 8) {
            c->s.x[0] ^= LOADBYTES(c->buf, 8);
            c->s.x[1] ^= LOADBYTES(c->buf + 8, c->buf_len - 8);
            c->s.x[1] ^= PAD(c->buf_len - 8);
        } else {
            c->s.x[0] ^= LOADBYTES(c->buf, c->buf_len);
            c->s.x[0] ^= PAD(c->buf_len);
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
            c->s.x[0] ^= LOADBYTES(c->buf, 8);
            c->s.x[1] ^= LOADBYTES(c->buf + 8, c->buf_len - 8);
            STOREBYTES(out, c->s.x[0], 8);
            STOREBYTES(out + 8, c->s.x[1], c->buf_len - 8);
        } else {
            uint64_t c0 = LOADBYTES(c->buf, 8);
            uint64_t c1 = LOADBYTES(c->buf + 8, c->buf_len - 8);
            STOREBYTES(out, c->s.x[0] ^ c0, 8);
            STOREBYTES(out + 8, c->s.x[1] ^ c1, c->buf_len - 8);
            c->s.x[0] = c0;
            c->s.x[1] = CLEARBYTES(c->s.x[1], c->buf_len - 8);
            c->s.x[1] |= c1;
        }

        c->s.x[1] ^= PAD(c->buf_len - 8);
    } else {
        if (c->flags & TSM_CIPH_FLAG_ENCRYPT) {
            c->s.x[0] ^= LOADBYTES(c->buf, c->buf_len);
            STOREBYTES(out, c->s.x[0], c->buf_len);
        } else {
            uint64_t c0 = LOADBYTES(c->buf, c->buf_len);
            STOREBYTES(out, c->s.x[0] ^ c0, c->buf_len);
            c->s.x[0] = CLEARBYTES(c->s.x[0], c->buf_len);
            c->s.x[0] |= c0;
        }

        c->s.x[0] ^= PAD(c->buf_len);
    }

    printstate("pad text", &c->s);
    *outl = c->buf_len;

    /* finalize */
    if (c->mode == TSM_ASCON_AEAD_128) {
        c->s.x[1] ^= c->K[0];
        c->s.x[2] ^= c->K[1];
    } else { // TSM_ASCON_AEAD_128A
        c->s.x[2] ^= c->K[0];
        c->s.x[3] ^= c->K[1];
    }

    printstate("final 1st key xor", &c->s);
    P12(&c->s);
    c->s.x[3] ^= c->K[0];
    c->s.x[4] ^= c->K[1];
    printstate("final 2nd key xor", &c->s);
    c->phase = ASCON_PHASE_FINAL;

    /* set tag */
    if (c->flags & TSM_CIPH_FLAG_ENCRYPT) {
        STOREBYTES(c->tag, c->s.x[3], 8);
        STOREBYTES(c->tag + 8, c->s.x[4], 8);
    } else {
        uint8_t t[16];
        STOREBYTES(t, c->s.x[3], 8);
        STOREBYTES(t + 8, c->s.x[4], 8);

        /* verify tag (constant time) */
        int i, result = 0;
        for (i = 0; i < 16; ++i)
            result |= c->tag[i] ^ t[i];

        result = (((result - 1) >> 8) & 1) - 1;
        if (result != 0)
            return ERRLOG(TSM_ERR_AEAD_VERIFY_FAILED);
    }

    return TSM_OK;
}

void *tsm_ascon_aead_init(int scheme, const unsigned char *key, const unsigned char *nonce,
                          int flags)
{
    if (key == NULL || nonce == NULL) {
        LOGE(tsm_err2str(TSM_ERR_PASS_NULL_PARAM));
        return NULL;
    }

    TSM_ASCON_CTX *ctx = tsm_calloc(sizeof(TSM_ASCON_CTX));

    if (ctx == NULL) {
        LOGE(tsm_err2str(TSM_ERR_MALLOC_FAILED));
        return NULL;
    }

    ctx->mode = scheme;
    ctx->flags = flags;

    /* load key and nonce */
    ctx->K[0] = LOADBYTES(key, 8);
    ctx->K[1] = LOADBYTES(key + 8, 8);
    ctx->N[0] = LOADBYTES(nonce, 8);
    ctx->N[1] = LOADBYTES(nonce + 8, 8);

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
        LOGE(tsm_err2str(TSM_ERR_INVALID_ASCON_SCHEME));
        tsm_free(ctx);
        return NULL;
    }

    ctx->s.x[1] = ctx->K[0];
    ctx->s.x[2] = ctx->K[1];
    ctx->s.x[3] = ctx->N[0];
    ctx->s.x[4] = ctx->N[1];
    printstate("init 1st key xor", &ctx->s);
    P12(&ctx->s);
    ctx->s.x[3] ^= ctx->K[0];
    ctx->s.x[4] ^= ctx->K[1];
    printstate("init 2nd key xor", &ctx->s);
    ctx->phase = ASCON_PHASE_INIT;
    return ctx;
}

void tsm_ascon_aead_clean(void *ctx)
{
    if (ctx != NULL) {
        TSM_ASCON_CTX *c = (TSM_ASCON_CTX *)ctx;
        tsm_memzero(c, sizeof(*c));
        tsm_free(c);
    }
}

int tsm_ascon_aead_set_tag(void *ctx, const unsigned char *tag)
{
    if (ctx == NULL || tag == NULL)
        return ERRLOG(TSM_ERR_PASS_NULL_PARAM);

    TSM_ASCON_CTX *c = (TSM_ASCON_CTX *)ctx;

    if (c->flags & TSM_CIPH_FLAG_ENCRYPT) {
        return ERRLOG(TSM_ERR_INVALID_OPERATION);
    } else {
        memcpy(c->tag, tag, sizeof(c->tag));
    }

    return TSM_OK;
}

int tsm_ascon_aead_get_tag(void *ctx, unsigned char *tag)
{
    if (ctx == NULL || tag == NULL)
        return ERRLOG(TSM_ERR_PASS_NULL_PARAM);

    TSM_ASCON_CTX *c = (TSM_ASCON_CTX *)ctx;

    if (c->flags & TSM_CIPH_FLAG_ENCRYPT) {
        memcpy(tag, c->tag, sizeof(c->tag));
    } else {
        return ERRLOG(TSM_ERR_INVALID_OPERATION);
    }

    return TSM_OK;
}

int tsm_ascon_aead_oneshot(int scheme, const unsigned char *key, const unsigned char *nonce,
                           const unsigned char *ad, int adl, const unsigned char *in, int inl,
                           unsigned char *out, int *outl, int flags)
{
    int tmplen = 0;
    void *ctx;

    if (key == NULL || nonce == NULL || out == NULL || outl == NULL)
        return ERRLOG(TSM_ERR_PASS_NULL_PARAM);

    ctx = tsm_ascon_aead_init(scheme, key, nonce, flags);
    if (ctx == NULL)
        return TSM_FAILED;

    /* Expect tag after ciphertext */
    if (flags & TSM_CIPH_FLAG_DECRYPT) {
        if (tsm_ascon_aead_set_tag(ctx, in + inl - TSM_ASCON_AEAD_TAG_LEN) != TSM_OK) {
            tsm_ascon_aead_clean(ctx);
            return TSM_FAILED;
        }
        inl -= TSM_ASCON_AEAD_TAG_LEN;
    }

    if (ad != NULL && adl > 0) {
        if (tsm_ascon_aead_update(ctx, ad, adl, NULL, NULL) != TSM_OK) {
            tsm_ascon_aead_clean(ctx);
            return TSM_FAILED;
        }
    }

    if (in != NULL && inl > 0) {
        if (tsm_ascon_aead_update(ctx, in, inl, out, &tmplen) != TSM_OK) {
            tsm_ascon_aead_clean(ctx);
            return TSM_FAILED;
        }
    }

    if (tsm_ascon_aead_final(ctx, out + tmplen, outl) != TSM_OK) {
        tsm_ascon_aead_clean(ctx);
        return TSM_FAILED;
    }

    *outl += tmplen;

    /* Append tag to ciphertext */
    if (flags & TSM_CIPH_FLAG_ENCRYPT) {
        if (tsm_ascon_aead_get_tag(ctx, out + *outl) != TSM_OK) {
            tsm_ascon_aead_clean(ctx);
            return TSM_FAILED;
        }

        *outl += TSM_ASCON_AEAD_TAG_LEN;
    }

    tsm_ascon_aead_clean(ctx);
    return TSM_OK;
}
