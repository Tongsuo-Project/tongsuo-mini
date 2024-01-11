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
 * @file oscore_context.h
 * @brief An implementation of the Object Security for Constrained RESTful
 * Enviornments (RFC 8613).
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted to libcoap; added group communication
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 * adapted for Tongsuo-mini integration
 *      K1 <dongbeiouba@gmail.com>
 */

#if !defined(TSM_OSCORE_CONTEXT_H)
# define TSM_OSCORE_CONTEXT_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <tongsuo/oscore_cose.h>
# include <tongsuo/mem.h>
# include <stdlib.h>

/* AES-256 */
# define CONTEXT_MAX_KEY_LEN 32

# define OSCORE_SEQ_MAX      (((uint64_t)1 << 40) - 1)

typedef enum oscore_mode_e {
    OSCORE_MODE_SINGLE = 0, /* Vanilla RFC8613 support */
    OSCORE_MODE_GROUP,      /* TODO draft-ietf-core-oscore-groupcomm */
    OSCORE_MODE_PAIRWISE    /* TODO draft-ietf-core-oscore-groupcomm */
} oscore_mode_t;

typedef struct oscore_ctx_s oscore_ctx_t;
typedef struct oscore_sender_ctx_s oscore_sender_ctx_t;
typedef struct oscore_recipient_ctx_s oscore_recipient_ctx_t;
typedef struct oscore_association_s oscore_association_t;
typedef struct tsm_oscore_conf_s TSM_OSCORE_CONF;

typedef int (*tsm_oscore_save_seq_num_t)(uint64_t sender_seq_num, void *param);

struct tsm_oscore_conf_s {
    TSM_STR *master_secret;      /* Common Master Secret */
    TSM_STR *master_salt;        /* Common Master Salt */
    TSM_STR *sender_id;          /* Sender ID (i.e. local our id) */
    TSM_STR *id_context;         /* Common ID context */
    TSM_STR **recipient_id;      /* Recipient ID (i.e. remote peer id)
                                             Array of recipient_id */
    uint32_t recipient_id_count; /* Number of recipient_id entries */
    uint32_t replay_window;      /* Replay window size
                                             Use COAP_OSCORE_DEFAULT_REPLAY_WINDOW */
    uint32_t ssn_freq;           /* Sender Seq Num update frequency */
    cose_alg_t aead_alg;         /* Set to one of COSE_ALGORITHM_AES* */
    cose_hkdf_alg_t hkdf_alg;    /* Set to one of COSE_HKDF_ALG_* */
    uint32_t rfc8613_b_1_2;      /* 1 if rfc8613 B.1.2 enabled else 0 */
    uint32_t rfc8613_b_2;        /* 1 if rfc8613 B.2 protocol else 0 */
    /* General Testing */
    uint32_t break_sender_key;    /* 1 if sender key to be broken, else 0 */
    uint32_t break_recipient_key; /* 1 if recipient key to be broken, else 0 */
    /* SSN handling (not in oscore_config[]) */
    tsm_oscore_save_seq_num_t save_seq_num_func; /* Called every seq num
                                                     change */
    void *save_seq_num_func_param;               /* Passed to save_seq_num_func() */
    uint64_t start_seq_num;                      /* Used for ssn_freq updating */
};

struct oscore_ctx_s {
    struct oscore_ctx_s *next;
    TSM_STR *master_secret;
    TSM_STR *master_salt;
    TSM_STR *common_iv;  /* Derived from Master Secret,
                                      Master Salt, and ID Context */
    TSM_STR *id_context; /* contains GID in case of group */
    oscore_sender_ctx_t *sender_context;
    oscore_recipient_ctx_t *recipient_chain;
    cose_alg_t aead_alg;
    cose_hkdf_alg_t hkdf_alg;
    oscore_mode_t mode;
    uint8_t rfc8613_b_1_2; /* 1 if rfc8613 B.1.2 enabled else 0 */
    uint8_t rfc8613_b_2;   /* 1 if rfc8613 B.2 protocol else 0 */
    uint32_t ssn_freq;     /* Sender Seq Num update frequency */
    uint32_t replay_window_size;
    tsm_oscore_save_seq_num_t save_seq_num_func; /* Called every seq num
                                                     change */
    void *save_seq_num_func_param;               /* Passed to save_seq_num_func() */
};

struct oscore_sender_ctx_s {
    uint64_t seq;
    uint64_t next_seq; /* Used for ssn_freq updating */
    TSM_STR *sender_key;
    TSM_STR *sender_id;
};

struct oscore_recipient_ctx_s {
    oscore_recipient_ctx_t *next_recipient; /* This field allows recipient chaining */
    oscore_ctx_t *osc_ctx;
    uint64_t last_seq;
    uint64_t sliding_window;
    uint64_t rollback_sliding_window;
    uint64_t rollback_last_seq;
    TSM_STR *recipient_key;
    TSM_STR *recipient_id;
    uint8_t echo_value[8];
    uint8_t initial_state;
};

struct oscore_association_s {
    /* FIXME: change link list to hash table */
    struct oscore_association_s *next;
    oscore_recipient_ctx_t *recipient_ctx;
    void *sent_pdu;
    TSM_STR *token;
    TSM_STR *aad;
    TSM_STR *nonce;
    TSM_STR *partial_iv;
    uint64_t last_seen;
    uint8_t is_observe;
};

/* Create a new context of oscore, based on oscore_conf. The context should be freed by calling
 * tsm_oscore_ctx_free() after use. */
oscore_ctx_t *tsm_oscore_ctx_new(TSM_OSCORE_CONF *oscore_conf);
/* Frees up the context osc_ctx of oscore. */
void tsm_oscore_ctx_free(oscore_ctx_t *osc_ctx);
/* Duplicates the context o_osc_ctx of oscore with sender_id, recipient_id and id_context. The
 * context should be freed by calling tsm_oscore_ctx_free() after use. */
oscore_ctx_t *tsm_oscore_ctx_dup(oscore_ctx_t *o_osc_ctx,
                                 TSM_STR *sender_id,
                                 TSM_STR *recipient_id,
                                 TSM_STR *id_context);
/* Updates the id context within osc_ctx with id_context. */
void tsm_oscore_ctx_update(oscore_ctx_t *osc_ctx, TSM_STR *id_context);
/* Adds a new recipient to osc_ctx with recipient id rid. break_key is intended for testing. Returns
 * recipient context on success, otherwise returns NULL. */
oscore_recipient_ctx_t *tsm_oscore_add_recipient(oscore_ctx_t *osc_ctx, TSM_STR *rid,
                                                 uint32_t break_key);
/* Deletes the recipient with recipient id rid within osc_ctx. If found and deleted successfully,
 * TSM_OK is returned. */
int tsm_oscore_delete_recipient(oscore_ctx_t *osc_ctx, TSM_STR *rid);
/* Log tsm_str in hex format. */
void tsm_oscore_log_hex_value(int level, const char *name, TSM_STR *value);
/* Log C str. */
void tsm_oscore_log_char_value(int level, const char *name, const char *value);
/* Finds recipient within osc_ctc. If recipient id in rcpkey_id is not empty, the id is used as a
 * key. If oscore_r2 is not NULL, oscore_r2 is compared to id context within osc_ctx. If ctxkey_id
 * is not NULL, ctxkey_id is compared to id context within osc_ctx. If found, the recipient context
 * is returned, otherwise NULL is returned. */
oscore_recipient_ctx_t *tsm_oscore_find_recipient(const oscore_ctx_t *osc_ctx,
                                                  const TSM_STR *rcpkey_id,
                                                  const TSM_STR *ctxkey_id,
                                                  uint8_t *oscore_r2);
/* Create new association with token, recipient context, aad, nonce, partial iv. The returned
 * association should be freed by calling tsm_oscore_association_free() after use. */
oscore_association_t *tsm_oscore_association_new(TSM_STR *token,
                                                 oscore_recipient_ctx_t *recipient_ctx,
                                                 TSM_STR *aad,
                                                 TSM_STR *nonce,
                                                 TSM_STR *partial_iv,
                                                 int is_observe);
/* Frees up the association association. */
void tsm_oscore_association_free(oscore_association_t *association);
/* Finds a association within chain with token. If found, the association is returned, otherwise
 * NULL is returned. */
oscore_association_t *tsm_oscore_association_find(oscore_association_t *chain, TSM_STR *token);
/* Deletes the association on chain. */
void tsm_oscore_association_delete(oscore_association_t **chain, oscore_association_t *association);
/* Deletes all associations on chain by calling free_func. */
void tsm_oscore_association_free_all(oscore_association_t *chain,
                                     void (*free_func)(oscore_association_t *));
# ifdef __cplusplus
}
# endif
#endif
