/*
 * Copyright (c) 2018, SICS, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * @file oscore_context.c
 * @brief An implementation of the Object Security for Constrained RESTful
 * Environments (RFC 8613).
 *
 * \author Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 * adapted for Tongsuo-mini integration
 *      K1 <dongbeiouba@gmail.com>
 */

#include "internal/log.h"
#include "internal/oscore_crypto.h"
#include <tongsuo/oscore.h>
#include <tongsuo/oscore_context.h>
#include <tongsuo/oscore_cbor.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t compose_info(uint8_t *buffer,
                           size_t buf_size,
                           uint8_t alg,
                           TSM_STR *id,
                           TSM_STR *id_context,
                           TSM_STR *type,
                           size_t out_len)
{
    size_t ret = 0;
    size_t rem_size = buf_size;

    ret += tsm_oscore_cbor_put_array(&buffer, &rem_size, 5);
    ret += tsm_oscore_cbor_put_bytes(&buffer, &rem_size, id ? id->s : NULL, id ? id->length : 0);
    if (id_context != NULL && id_context->length > 0) {
        ret += tsm_oscore_cbor_put_bytes(&buffer, &rem_size, id_context->s, id_context->length);
    } else {
        ret += tsm_oscore_cbor_put_nil(&buffer, &rem_size);
    }
    ret += tsm_oscore_cbor_put_unsigned(&buffer, &rem_size, alg);
    ret += tsm_oscore_cbor_put_text(&buffer, &rem_size, (const char *)type->s, type->length);
    ret += tsm_oscore_cbor_put_unsigned(&buffer, &rem_size, out_len);
    return ret;
}

uint8_t oscore_bytes_equal(uint8_t *a_ptr, uint8_t a_len, uint8_t *b_ptr, uint8_t b_len)
{
    if (a_len != b_len) {
        return 0;
    }

    if (memcmp(a_ptr, b_ptr, a_len) == 0) {
        return 1;
    } else {
        return 0;
    }
}

static void oscore_free_recipient(oscore_recipient_ctx_t *recipient)
{
    tsm_str_free(recipient->recipient_id);
    tsm_str_free(recipient->recipient_key);
    tsm_free(recipient);
}

void tsm_oscore_ctx_free(oscore_ctx_t *osc_ctx)
{
    if (osc_ctx == NULL)
        return;

    if (osc_ctx->sender_context) {
        tsm_str_free(osc_ctx->sender_context->sender_id);
        tsm_str_free(osc_ctx->sender_context->sender_key);
        tsm_free(osc_ctx->sender_context);
    }

    while (osc_ctx->recipient_chain) {
        oscore_recipient_ctx_t *next = osc_ctx->recipient_chain->next_recipient;

        oscore_free_recipient(osc_ctx->recipient_chain);
        osc_ctx->recipient_chain = next;
    }

    tsm_str_free(osc_ctx->master_secret);
    tsm_str_free(osc_ctx->master_salt);
    tsm_str_free(osc_ctx->id_context);
    tsm_str_free(osc_ctx->common_iv);

    tsm_free(osc_ctx);
}

oscore_recipient_ctx_t *tsm_oscore_find_recipient(const oscore_ctx_t *osc_ctx,
                                                  const TSM_STR *rcpkey_id,
                                                  const TSM_STR *ctxkey_id,
                                                  uint8_t *oscore_r2)
{
    int ok = 0;
    oscore_recipient_ctx_t *rpt = osc_ctx->recipient_chain;

    while (rpt) {
        ok = 0;
        if (rcpkey_id->length == rpt->recipient_id->length) {
            if (rcpkey_id->length != 0)
                ok = memcmp(rpt->recipient_id->s, rcpkey_id->s, rcpkey_id->length) != 0;
            if (oscore_r2) {
                if (osc_ctx->id_context != NULL && osc_ctx->id_context->length > 8) {
                    ok = ok + (memcmp(osc_ctx->id_context->s, oscore_r2, 8) != 0);
                } else {
                    ok += 1;
                }
            } else if (ctxkey_id) {
                if (osc_ctx->id_context != NULL) {
                    if (ctxkey_id->length != osc_ctx->id_context->length)
                        ok += 1;
                    else
                        ok = ok
                             + (memcmp(osc_ctx->id_context->s, ctxkey_id->s, ctxkey_id->length)
                                != 0);
                } else if (ctxkey_id->length > 0)
                    ok += 1;
            }
            if (ok == 0)
                return rpt;
        }
        rpt = rpt->next_recipient;
    } /* while rpt */

    return NULL;
}

static void oscore_convert_to_hex(const uint8_t *src, size_t src_len, char *dest, size_t dst_len)
{
    /*
     * Last output character will be '\000'
     * (If output undersized, add trailing ... to indicate this.
     */
    size_t space = (dst_len - 4) / 3;
    uint32_t qq;

    for (qq = 0; qq < src_len && qq < space; qq++) {
        char tmp = src[qq] >> 4;
        if (tmp > 9)
            tmp = tmp + 0x61 - 10;
        else
            tmp = tmp + 0x30;
        dest[qq * 3] = tmp;
        tmp = src[qq] & 0xf;
        if (tmp > 9)
            tmp = tmp + 0x61 - 10;
        else
            tmp = tmp + 0x30;
        dest[qq * 3 + 1] = tmp;
        dest[qq * 3 + 2] = 0x20;
    }
    if (qq != src_len) {
        dest[qq * 3] = '.';
        dest[qq * 3 + 1] = '.';
        dest[qq * 3 + 2] = '.';
        qq++;
    }
    dest[qq * 3] = 0;
}

#define OSCORE_LOG_SIZE 16
void tsm_oscore_log_hex_value(int level, const char *name, TSM_STR *value)
{
    size_t i;

    if (value == NULL) {
        tsm_log(level, "    %-16s\n", name);
        return;
    }
    if (value->length == 0) {
        tsm_log(level, "    %-16s <>\n", name);
        return;
    }
    for (i = 0; i < value->length; i += OSCORE_LOG_SIZE) {
        char number[3 * OSCORE_LOG_SIZE + 4];

        oscore_convert_to_hex(&value->s[i],
                              value->length - i > OSCORE_LOG_SIZE ? OSCORE_LOG_SIZE
                                                                  : value->length - i,
                              number,
                              sizeof(number));
        tsm_log(level, "    %-16s %s\n", i == 0 ? name : "", number);
    }
}

void tsm_oscore_log_char_value(int level, const char *name, const char *value)
{
    tsm_log(level, "    %-16s %s\n", name, value);
}

static TSM_STR *oscore_build_key(oscore_ctx_t *osc_ctx, TSM_STR *id, TSM_STR *type, size_t out_len)
{
    uint8_t info_buffer[80];
    size_t info_len;
    uint8_t hkdf_tmp[CONTEXT_MAX_KEY_LEN];

    info_len = compose_info(info_buffer,
                            sizeof(info_buffer),
                            osc_ctx->aead_alg,
                            id,
                            osc_ctx->id_context,
                            type,
                            out_len);
    if (info_len == 0 || info_len > sizeof(info_buffer))
        return NULL;

    if (oscore_hkdf(osc_ctx->hkdf_alg,
                    osc_ctx->master_salt,
                    osc_ctx->master_secret,
                    info_buffer,
                    info_len,
                    hkdf_tmp,
                    out_len)
        != TSM_OK)
        return NULL;
    return tsm_str_new(hkdf_tmp, out_len);
}

static void oscore_log_context(oscore_ctx_t *osc_ctx, const char *heading)
{
    char buffer[30];
    oscore_recipient_ctx_t *next = osc_ctx->recipient_chain;
    size_t count = 0;

    LOGI("%s\n", heading);
    tsm_oscore_log_char_value(TSM_LOG_INFO, "AEAD alg",
                              tsm_cose_get_alg_name(osc_ctx->aead_alg, buffer, sizeof(buffer)));
    tsm_oscore_log_char_value(TSM_LOG_INFO, "HKDF alg",
                              tsm_cose_get_hkdf_alg_name(osc_ctx->hkdf_alg, buffer,
                                                         sizeof(buffer)));
    tsm_oscore_log_hex_value(TSM_LOG_INFO, "ID Context", osc_ctx->id_context);
    tsm_oscore_log_hex_value(TSM_LOG_INFO, "Master Secret", osc_ctx->master_secret);
    tsm_oscore_log_hex_value(TSM_LOG_INFO, "Master Salt", osc_ctx->master_salt);
    tsm_oscore_log_hex_value(TSM_LOG_INFO, "Common IV", osc_ctx->common_iv);
    tsm_oscore_log_hex_value(TSM_LOG_INFO, "Sender ID", osc_ctx->sender_context->sender_id);
    tsm_oscore_log_hex_value(TSM_LOG_INFO, "Sender Key", osc_ctx->sender_context->sender_key);
    while (next) {
        snprintf(buffer, sizeof(buffer), "Recipient ID[%zu]", count);
        tsm_oscore_log_hex_value(TSM_LOG_INFO, buffer, next->recipient_id);
        snprintf(buffer, sizeof(buffer), "Recipient Key[%zu]", count);
        tsm_oscore_log_hex_value(TSM_LOG_INFO, buffer, next->recipient_key);
        count++;
        next = next->next_recipient;
    }
}

void tsm_oscore_ctx_update(oscore_ctx_t *osc_ctx, TSM_STR *id_context)
{
    TSM_STR *temp;

    /* Update with new ID Context */
    tsm_str_free(osc_ctx->id_context);
    osc_ctx->id_context = id_context;

    /* Update sender_key, recipient_key and common_iv */
    temp = osc_ctx->sender_context->sender_key;
    osc_ctx->sender_context->sender_key = oscore_build_key(osc_ctx,
                                                           osc_ctx->sender_context->sender_id,
                                                           tsm_str("Key"),
                                                           tsm_cose_key_len(osc_ctx->aead_alg));
    if (!osc_ctx->sender_context->sender_key)
        osc_ctx->sender_context->sender_key = temp;
    else
        tsm_str_free(temp);
    temp = osc_ctx->recipient_chain->recipient_key;
    osc_ctx->recipient_chain->recipient_key =
        oscore_build_key(osc_ctx,
                         osc_ctx->recipient_chain->recipient_id,
                         tsm_str("Key"),
                         tsm_cose_key_len(osc_ctx->aead_alg));
    if (!osc_ctx->recipient_chain->recipient_key)
        osc_ctx->recipient_chain->recipient_key = temp;
    else
        tsm_str_free(temp);
    temp = osc_ctx->common_iv;
    osc_ctx->common_iv =
        oscore_build_key(osc_ctx, NULL, tsm_str("IV"), tsm_cose_nonce_len(osc_ctx->aead_alg));
    if (!osc_ctx->common_iv)
        osc_ctx->common_iv = temp;
    else
        tsm_str_free(temp);

    oscore_log_context(osc_ctx, "Updated Common context");
}

oscore_ctx_t *tsm_oscore_ctx_dup(oscore_ctx_t *o_osc_ctx,
                                 TSM_STR *sender_id,
                                 TSM_STR *recipient_id,
                                 TSM_STR *id_context)
{
    oscore_ctx_t *osc_ctx = NULL;
    oscore_sender_ctx_t *sender_ctx = NULL;
    TSM_STR *copy_rid = NULL;

    osc_ctx = tsm_calloc(sizeof(oscore_ctx_t));
    if (osc_ctx == NULL)
        goto error;

    sender_ctx = tsm_calloc(sizeof(oscore_sender_ctx_t));
    if (sender_ctx == NULL)
        goto error;

    osc_ctx->sender_context = sender_ctx;
    if (o_osc_ctx->master_secret)
        osc_ctx->master_secret = tsm_str_dup(o_osc_ctx->master_secret);
    if (o_osc_ctx->master_salt)
        osc_ctx->master_salt = tsm_str_dup(o_osc_ctx->master_salt);
    osc_ctx->aead_alg = o_osc_ctx->aead_alg;
    osc_ctx->hkdf_alg = o_osc_ctx->hkdf_alg;
    if (id_context)
        osc_ctx->id_context = tsm_str_dup(id_context);
    osc_ctx->ssn_freq = o_osc_ctx->ssn_freq;
    osc_ctx->replay_window_size = o_osc_ctx->replay_window_size;
    osc_ctx->rfc8613_b_1_2 = o_osc_ctx->rfc8613_b_1_2;
    osc_ctx->rfc8613_b_2 = o_osc_ctx->rfc8613_b_2;
    osc_ctx->save_seq_num_func = o_osc_ctx->save_seq_num_func;
    osc_ctx->save_seq_num_func_param = o_osc_ctx->save_seq_num_func_param;

    if (o_osc_ctx->master_secret) {
        /* sender_ key */
        sender_ctx->sender_key = oscore_build_key(osc_ctx, sender_id, tsm_str("Key"),
                                                  tsm_cose_key_len(osc_ctx->aead_alg));
        if (!sender_ctx->sender_key)
            goto error;

        /* common IV */
        osc_ctx->common_iv =
            oscore_build_key(osc_ctx, NULL, tsm_str("IV"), tsm_cose_nonce_len(osc_ctx->aead_alg));
        if (!osc_ctx->common_iv)
            goto error;
    }

    /*
     * Need to set the last Sender Seq Num based on ssn_freq
     * The value should only change if there is a change to ssn_freq
     * and (potentially) be lower than seq, then save_seq_num_func() is
     * immediately called on next SSN update.
     */
    sender_ctx->next_seq = 0;
    sender_ctx->seq = 0;

    sender_ctx->sender_id = tsm_str_dup(sender_id);
    if (sender_ctx->sender_id == NULL)
        goto error;

    copy_rid = tsm_str_dup(recipient_id);
    if (copy_rid == NULL)
        goto error;

    if (tsm_oscore_add_recipient(osc_ctx, copy_rid, 0) == NULL)
        goto error;

    oscore_log_context(osc_ctx, "New Common context");

    return osc_ctx;

error:
    tsm_oscore_ctx_free(osc_ctx);
    return NULL;
}

oscore_ctx_t *tsm_oscore_ctx_new(TSM_OSCORE_CONF *oscore_conf)
{
    oscore_ctx_t *osc_ctx = NULL;
    oscore_sender_ctx_t *sender_ctx = NULL;
    size_t i;

    osc_ctx = tsm_calloc(sizeof(oscore_ctx_t));
    if (osc_ctx == NULL)
        goto error;

    sender_ctx = tsm_calloc(sizeof(oscore_sender_ctx_t));
    if (sender_ctx == NULL)
        goto error;

    osc_ctx->sender_context = sender_ctx;
    osc_ctx->master_secret = tsm_str_dup(oscore_conf->master_secret);
    osc_ctx->master_salt = tsm_str_dup(oscore_conf->master_salt);
    osc_ctx->aead_alg = oscore_conf->aead_alg;
    osc_ctx->hkdf_alg = oscore_conf->hkdf_alg;
    osc_ctx->id_context = tsm_str_dup(oscore_conf->id_context);
    osc_ctx->ssn_freq = oscore_conf->ssn_freq ? oscore_conf->ssn_freq : 1;
    osc_ctx->replay_window_size =
        oscore_conf->replay_window ? oscore_conf->replay_window : TSM_OSCORE_DEFAULT_REPLAY_WINDOW;
    osc_ctx->rfc8613_b_1_2 = oscore_conf->rfc8613_b_1_2;
    osc_ctx->rfc8613_b_2 = oscore_conf->rfc8613_b_2;
    osc_ctx->save_seq_num_func = oscore_conf->save_seq_num_func;
    osc_ctx->save_seq_num_func_param = oscore_conf->save_seq_num_func_param;

    if (oscore_conf->master_secret) {
        /* sender_ key */
        if (oscore_conf->break_sender_key)
            /* Interop testing */
            sender_ctx->sender_key =
                oscore_build_key(osc_ctx, oscore_conf->sender_id, tsm_str("BAD"),
                                 tsm_cose_key_len(osc_ctx->aead_alg));
        else
            sender_ctx->sender_key =
                oscore_build_key(osc_ctx, oscore_conf->sender_id, tsm_str("Key"),
                                 tsm_cose_key_len(osc_ctx->aead_alg));
        if (!sender_ctx->sender_key)
            goto error;

        /* common IV */
        osc_ctx->common_iv =
            oscore_build_key(osc_ctx, NULL, tsm_str("IV"), tsm_cose_nonce_len(osc_ctx->aead_alg));
        if (!osc_ctx->common_iv)
            goto error;
    }

    /*
     * Need to set the last Sender Seq Num based on ssn_freq
     * The value should only change if there is a change to ssn_freq
     * and (potentially) be lower than seq, then save_seq_num_func() is
     * immediately called on next SSN update.
     */
    sender_ctx->next_seq =
        oscore_conf->start_seq_num
        - (oscore_conf->start_seq_num % (oscore_conf->ssn_freq > 0 ? oscore_conf->ssn_freq : 1));

    sender_ctx->sender_id = tsm_str_dup(oscore_conf->sender_id);
    sender_ctx->seq = oscore_conf->start_seq_num;

    for (i = 0; i < oscore_conf->recipient_id_count; i++) {
        if (tsm_oscore_add_recipient(osc_ctx, oscore_conf->recipient_id[i],
                                     oscore_conf->break_recipient_key)
            == NULL) {
            LOGE("OSCORE: Failed to add Client ID\n");
            goto error;
        }
    }
    oscore_log_context(osc_ctx, "Common context");

    return osc_ctx;

error:
    tsm_oscore_ctx_free(osc_ctx);
    return NULL;
}

oscore_recipient_ctx_t *tsm_oscore_add_recipient(oscore_ctx_t *osc_ctx, TSM_STR *rid,
                                                 uint32_t break_key)
{
    oscore_recipient_ctx_t *rcp_ctx = osc_ctx->recipient_chain;
    oscore_recipient_ctx_t *recipient_ctx = NULL;

    if (rid->length > 7) {
        LOGE("tsm_oscore_add_recipient: Maximum size of recipient_id is 7 bytes\n");
        return NULL;
    }
    /* Check this is not a duplicate recipient id */
    while (rcp_ctx) {
        if (rcp_ctx->recipient_id->length == rid->length
            && memcmp(rcp_ctx->recipient_id->s, rid->s, rid->length) == 0) {
            tsm_str_free(rid);
            return NULL;
        }
        rcp_ctx = rcp_ctx->next_recipient;
    }
    recipient_ctx = (oscore_recipient_ctx_t *)tsm_calloc(sizeof(oscore_recipient_ctx_t));
    if (recipient_ctx == NULL)
        return NULL;

    if (osc_ctx->master_secret) {
        if (break_key)
            /* Interop testing */
            recipient_ctx->recipient_key =
                oscore_build_key(osc_ctx, rid, tsm_str("BAD"), tsm_cose_key_len(osc_ctx->aead_alg));
        else
            recipient_ctx->recipient_key =
                oscore_build_key(osc_ctx, rid, tsm_str("Key"), tsm_cose_key_len(osc_ctx->aead_alg));
        if (!recipient_ctx->recipient_key) {
            tsm_free(recipient_ctx);
            return NULL;
        }
    }

    recipient_ctx->recipient_id = tsm_str_dup(rid);
    recipient_ctx->initial_state = 1;
    recipient_ctx->osc_ctx = osc_ctx;

    rcp_ctx = osc_ctx->recipient_chain;
    recipient_ctx->next_recipient = rcp_ctx;
    osc_ctx->recipient_chain = recipient_ctx;
    return recipient_ctx;
}

int tsm_oscore_delete_recipient(oscore_ctx_t *osc_ctx, TSM_STR *rid)
{
    oscore_recipient_ctx_t *prev = NULL;
    oscore_recipient_ctx_t *next = osc_ctx->recipient_chain;
    while (next) {
        if (next->recipient_id->length == rid->length
            && memcmp(next->recipient_id->s, rid->s, rid->length) == 0) {
            if (prev != NULL)
                prev->next_recipient = next->next_recipient;
            else
                osc_ctx->recipient_chain = next->next_recipient;
            oscore_free_recipient(next);
            return TSM_OK;
        }
        prev = next;
        next = next->next_recipient;
    }
    return TSM_ERR_NOT_FOUND;
}

void tsm_oscore_association_free(oscore_association_t *association)
{
    if (association) {
        tsm_str_free(association->token);
        tsm_str_free(association->aad);
        tsm_str_free(association->nonce);
        tsm_str_free(association->partial_iv);
        tsm_free(association);
    }
}

oscore_association_t *tsm_oscore_association_new(TSM_STR *token,
                                                 oscore_recipient_ctx_t *recipient_ctx,
                                                 TSM_STR *aad,
                                                 TSM_STR *nonce,
                                                 TSM_STR *partial_iv,
                                                 int is_observe)
{
    oscore_association_t *association;

    association = tsm_calloc(sizeof(oscore_association_t));
    if (association == NULL)
        return 0;

    association->recipient_ctx = recipient_ctx;
    association->is_observe = is_observe;

    association->token = tsm_str_dup(token);
    if (association->token == NULL)
        goto error;

    if (aad) {
        association->aad = tsm_str_dup(aad);
        if (association->aad == NULL)
            goto error;
    }

    if (nonce) {
        association->nonce = tsm_str_dup(nonce);
        if (association->nonce == NULL)
            goto error;
    }

    if (partial_iv) {
        association->partial_iv = tsm_str_dup(partial_iv);
        if (association->partial_iv == NULL)
            goto error;
    }

    return association;

error:
    tsm_oscore_association_free(association);
    return NULL;
}

oscore_association_t *tsm_oscore_association_find(oscore_association_t *chain, TSM_STR *token)
{
    while (chain) {
        if (tsm_str_equal(chain->token, token))
            return chain;

        chain = chain->next;
    }

    return NULL;
}

void tsm_oscore_association_delete(oscore_association_t **chain, oscore_association_t *association)
{
    oscore_association_t *iter;

    if (association == NULL)
        return;

    if (tsm_str_equal((*chain)->token, association->token)) {
        *chain = association->next;
    } else {
        iter = *chain;
        while (iter->next) {
            if (tsm_str_equal(iter->next->token, association->token)) {
                iter->next = association->next;
                break;
            }
            iter = iter->next;
        }
    }
}

void tsm_oscore_association_free_all(oscore_association_t *chain,
                                     void (*free_func)(oscore_association_t *))
{
    while (chain) {
        oscore_association_t *association = chain->next;
        free_func(chain);
        chain = association;
    }
}
