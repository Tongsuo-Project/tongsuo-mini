/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include "internal/log.h"
#include <tongsuo/oscore_context.h>
#include <tongsuo/oscore_cbor.h>
#include <tongsuo/oscore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

size_t tsm_oscore_prepare_e_aad(oscore_ctx_t *ctx,
                                cose_encrypt0_t *cose,
                                const uint8_t *oscore_option,
                                size_t oscore_option_len,
                                TSM_STR *sender_public_key,
                                uint8_t *external_aad_ptr,
                                size_t external_aad_size)
{
    size_t external_aad_len = 0;
    size_t rem_size = external_aad_size;

    (void)oscore_option;
    (void)oscore_option_len;
    (void)sender_public_key;

    if (ctx->mode != OSCORE_MODE_SINGLE)
        external_aad_len += tsm_oscore_cbor_put_array(&external_aad_ptr, &rem_size, 9);
    else
        external_aad_len += tsm_oscore_cbor_put_array(&external_aad_ptr, &rem_size, 5);

    /* oscore_version, always "1" */
    external_aad_len += tsm_oscore_cbor_put_unsigned(&external_aad_ptr, &rem_size, 1);

    if (ctx->mode == OSCORE_MODE_SINGLE) {
        /* Algoritms array with one item*/
        external_aad_len += tsm_oscore_cbor_put_array(&external_aad_ptr, &rem_size, 1);
        /* Encryption Algorithm   */
        external_aad_len += tsm_oscore_cbor_put_number(&external_aad_ptr, &rem_size, ctx->aead_alg);
    }
    /* request_kid */
    external_aad_len +=
        tsm_oscore_cbor_put_bytes(&external_aad_ptr, &rem_size, cose->key_id.s, cose->key_id.length);
    /* request_piv */
    external_aad_len += tsm_oscore_cbor_put_bytes(&external_aad_ptr,
                                                  &rem_size,
                                                  cose->partial_iv.s,
                                                  cose->partial_iv.length);
    /* options */
    /* Put integrity protected options, at present there are none. */
    external_aad_len += tsm_oscore_cbor_put_bytes(&external_aad_ptr, &rem_size, NULL, 0);

    return external_aad_len;
}

size_t tsm_oscore_encode_option_value(uint8_t *option_buffer,
                                      size_t option_buf_len,
                                      cose_encrypt0_t *cose,
                                      uint8_t group_flag,
                                      uint8_t appendix_b_2)
{
    size_t offset = 1;
    size_t rem_space = option_buf_len;

    (void)group_flag;
    if (cose->partial_iv.length > 5) {
        return 0;
    }
    option_buffer[0] = 0;

    if (cose->partial_iv.length > 0 && cose->partial_iv.length <= 5 && cose->partial_iv.s != NULL) {
        option_buffer[0] |= (0x07 & cose->partial_iv.length);
        memcpy(&(option_buffer[offset]), cose->partial_iv.s, cose->partial_iv.length);
        offset += cose->partial_iv.length;
        assert(rem_space > cose->partial_iv.length);
        rem_space -= cose->partial_iv.length;
    }

    if (cose->kid_context.length > 0 && cose->kid_context.s != NULL) {
        if (appendix_b_2) {
            /* Need to CBOR wrap kid_context - yuk! */
            uint8_t *ptr = &option_buffer[offset + 1];

            option_buffer[0] |= 0x10;
            option_buffer[offset] = (uint8_t)tsm_oscore_cbor_put_bytes(&ptr,
                                                                       &rem_space,
                                                                       cose->kid_context.s,
                                                                       cose->kid_context.length);
            offset += option_buffer[offset] + 1;
        } else {
            option_buffer[0] |= 0x10;
            option_buffer[offset] = (uint8_t)cose->kid_context.length;
            offset++;
            memcpy(&(option_buffer[offset]),
                   cose->kid_context.s,
                   (uint8_t)cose->kid_context.length);
            offset += cose->kid_context.length;
            assert(rem_space > cose->kid_context.length);
            rem_space -= cose->kid_context.length;
        }
    }

    if (cose->key_id.s != NULL) {
        option_buffer[0] |= 0x08;
        if (cose->key_id.length) {
            memcpy(&(option_buffer[offset]), cose->key_id.s, cose->key_id.length);
            offset += cose->key_id.length;
            assert(rem_space > cose->key_id.length);
            rem_space -= cose->key_id.length;
        }
    }

    if (offset == 1 && option_buffer[0] == 0) {
        /* If option_value is 0x00 it should be empty. */
        offset = 0;
    }
    assert(offset <= option_buf_len);
    cose->oscore_option.s = option_buffer;
    cose->oscore_option.length = offset;
    return offset;
}

int tsm_oscore_decode_option_value(const uint8_t *opt_value,
                                   size_t option_len,
                                   cose_encrypt0_t *cose)
{
    uint8_t partial_iv_len = (opt_value[0] & 0x07);
    size_t offset = 1;

    cose->oscore_option.s = opt_value;
    cose->oscore_option.length = option_len;

    if (option_len == 0)
        return TSM_OK; /* empty option */

    if (option_len > 255 || partial_iv_len == 6 || partial_iv_len == 7
        || (opt_value[0] & 0xC0) != 0) {
        return TSM_FAILED;
    }

    if ((opt_value[0] & 0x20) != 0) {
        return TSM_FAILED;
    }

    if (partial_iv_len != 0) {
        if (offset + partial_iv_len > option_len) {
            return TSM_FAILED;
        }
        tsm_cose_encrypt0_set_partial_iv(cose, &(opt_value[offset]), partial_iv_len);
        offset += partial_iv_len;
    }

    if ((opt_value[0] & 0x10) != 0) {
        TSM_STR kid_context;

        if (offset >= option_len)
            return TSM_FAILED;
        kid_context.length = opt_value[offset];
        offset++;
        if (offset + kid_context.length > option_len) {
            return TSM_FAILED;
        }
        kid_context.s = &(opt_value[offset]);
        tsm_cose_encrypt0_set_kid_context(cose, kid_context.s, kid_context.length);
        offset = offset + kid_context.length;
    }

    if ((opt_value[0] & 0x08) != 0) {
        if (option_len - offset < 0) {
            return TSM_FAILED;
        }

        tsm_cose_encrypt0_set_key_id(cose, &(opt_value[offset]), option_len - offset);
    }
    return TSM_OK;
}

size_t tsm_oscore_prepare_aad(const uint8_t *external_aad_buffer,
                              size_t external_aad_len,
                              uint8_t *aad_buffer,
                              size_t aad_size)
{
    size_t ret = 0;
    size_t rem_size = aad_size;
    char encrypt0[] = "Encrypt0";

    (void)aad_size; /* TODO */
    /* Creating the AAD */
    ret += tsm_oscore_cbor_put_array(&aad_buffer, &rem_size, 3);
    /* 1. "Encrypt0" */
    ret += tsm_oscore_cbor_put_text(&aad_buffer, &rem_size, encrypt0, strlen(encrypt0));
    /* 2. Empty h'' entry */
    ret += tsm_oscore_cbor_put_bytes(&aad_buffer, &rem_size, NULL, 0);
    /* 3. External AAD */
    ret += tsm_oscore_cbor_put_bytes(&aad_buffer, &rem_size, external_aad_buffer, external_aad_len);

    return ret;
}

void tsm_oscore_generate_nonce(cose_encrypt0_t *ptr,
                               oscore_ctx_t *ctx,
                               uint8_t *buffer,
                               uint8_t size)
{
    memset(buffer, 0, size);
    buffer[0] = (uint8_t)(ptr->key_id.length);
    memcpy(&(buffer[((size - 5) - ptr->key_id.length)]), ptr->key_id.s, ptr->key_id.length);
    memcpy(&(buffer[size - ptr->partial_iv.length]), ptr->partial_iv.s, ptr->partial_iv.length);
    for (int i = 0; i < size; i++) {
        buffer[i] = buffer[i] ^ (uint8_t)ctx->common_iv->s[i];
    }
}

static uint64_t decode_var_bytes8(const uint8_t *buf, size_t len)
{
    unsigned int i;
    uint64_t n = 0;
    for (i = 0; i < len && i < sizeof(uint64_t); ++i)
        n = (n << 8) + buf[i];

    return n;
}

int tsm_oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose)
{
    uint64_t incoming_seq = decode_var_bytes8(cose->partial_iv.s, cose->partial_iv.length);

    if (incoming_seq >= OSCORE_SEQ_MAX) {
        LOGW("OSCORE Replay protection, SEQ larger than SEQ_MAX.\n");
        return TSM_ERR_INVALID_SEQ;
    }

    ctx->rollback_last_seq = ctx->last_seq;
    ctx->rollback_sliding_window = ctx->sliding_window;

    /* Special case since we do not use unsigned int for seq */
    if (ctx->initial_state == 1) {
        ctx->initial_state = 0;
        /* bitfield. B0 biggest seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
        ctx->sliding_window = 1;
        ctx->last_seq = incoming_seq;
    } else if (incoming_seq > ctx->last_seq) {
        /* Update the replay window */
        uint64_t shift = incoming_seq - ctx->last_seq;
        ctx->sliding_window = ctx->sliding_window << shift;
        /* bitfield. B0 biggest seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
        ctx->sliding_window |= 1;
        ctx->last_seq = incoming_seq;
    } else if (incoming_seq == ctx->last_seq) {
        LOGW("OSCORE: Replay protection, replayed SEQ (%" PRIu64 ")\n", incoming_seq);
        return TSM_ERR_REPLAYED_SEQ;
    } else { /* incoming_seq < last_seq */
        uint64_t shift = ctx->last_seq - incoming_seq - 1;
        uint64_t pattern;

        if (shift > ctx->osc_ctx->replay_window_size || shift > 63) {
            LOGW("OSCORE: Replay protection, SEQ outside of replay window (%" PRIu64 " %" PRIu64
                 ")\n",
                 ctx->last_seq,
                 incoming_seq);
            return TSM_ERR_REPLAYED_SEQ;
        }
        /* seq + replay_window_size > last_seq */
        pattern = 1ULL << shift;
        if (ctx->sliding_window & pattern) {
            LOGW("OSCORE: Replay protection, replayed SEQ (%" PRIu64 ")\n", incoming_seq);
            return TSM_ERR_REPLAYED_SEQ;
        }
        /* bitfield. B0 biggest seq seen.  B1 seq-1 seen, B2 seq-2 seen etc. */
        ctx->sliding_window |= pattern;
    }
    LOGI("OSCORE: window 0x%" PRIx64 " seq-B0 %" PRIu64 " SEQ %" PRIu64 "\n",
         ctx->sliding_window,
         ctx->last_seq,
         incoming_seq);
    return TSM_OK;
}

int tsm_oscore_increment_sender_seq(oscore_ctx_t *ctx)
{
    ctx->sender_context->seq++;

    if (ctx->sender_context->seq >= OSCORE_SEQ_MAX) {
        return TSM_ERR_INVALID_SEQ;
    }

    return TSM_OK;
}

/*
 * tsm_oscore_roll_back_seq
 *
 * Restore the sequence number and replay-window to the previous state. This
 * is to be used when decryption fail.
 */
void tsm_oscore_roll_back_seq(oscore_recipient_ctx_t *ctx)
{
    if (ctx->rollback_sliding_window != 0) {
        ctx->sliding_window = ctx->rollback_sliding_window;
        ctx->rollback_sliding_window = 0;
    }
    if (ctx->rollback_last_seq != 0) {
        ctx->last_seq = ctx->rollback_last_seq;
        ctx->rollback_last_seq = 0;
    }
}

TSM_OSCORE_CONF *tsm_oscore_conf_new(void)
{
    TSM_OSCORE_CONF *oscf = tsm_calloc(sizeof(*oscf));

    oscf->replay_window = TSM_OSCORE_DEFAULT_REPLAY_WINDOW;
    oscf->ssn_freq = 1;
    oscf->aead_alg = COSE_ALGORITHM_ASCON_AEAD_16_128_128;
    oscf->hkdf_alg = COSE_HKDF_ALG_HKDF_ASCON_HASH;
    oscf->rfc8613_b_1_2 = 1;
    oscf->rfc8613_b_2 = 0;
    oscf->break_sender_key = 0;
    oscf->break_recipient_key = 0;

    return oscf;
}

void tsm_oscore_conf_free(TSM_OSCORE_CONF *oscf)
{
    tsm_str_free(oscf->master_secret);
    tsm_str_free(oscf->master_salt);
    tsm_str_free(oscf->sender_id);
    tsm_str_free(oscf->id_context);

    for (uint32_t i = 0; i < oscf->recipient_id_count; i++)
        tsm_str_free(oscf->recipient_id[i]);

    tsm_free(oscf->recipient_id);
}
