/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_OSCORE_H)
# define TSM_OSCORE_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <tongsuo/oscore_cose.h>
# include <tongsuo/oscore_context.h>
# include <tongsuo/mem.h>

/**
 * @ingroup internal_api
 * @addtogroup oscore_internal
 * @{
 */

# define TSM_OSCORE_DEFAULT_REPLAY_WINDOW 32

/* Estimate your header size, especially when using Proxy-Uri. */
# define COAP_MAX_HEADER_SIZE 70

/* OSCORE error messages  (to be moved elsewhere  */
# define OSCORE_DECRYPTION_ERROR    100
# define PACKET_SERIALIZATION_ERROR 102

/*
 * tsm_oscore_encode_option_value
 */
size_t tsm_oscore_encode_option_value(uint8_t *option_buffer,
                                      size_t option_buf_len,
                                      cose_encrypt0_t *cose,
                                      uint8_t group,
                                      uint8_t appendix_b_2);

/*
 * Decodes the OSCORE option value and places decoded values into the provided
 * cose structure */
int tsm_oscore_decode_option_value(const uint8_t *option_value,
                                   size_t option_len,
                                   cose_encrypt0_t *cose);

/* Creates AAD, creates External AAD and serializes it into the complete AAD
 * structure. Returns serialized size. */
size_t tsm_oscore_prepare_aad(const uint8_t *external_aad_buffer,
                              size_t external_aad_len,
                              uint8_t *aad_buffer,
                              size_t aad_size);

size_t tsm_oscore_prepare_e_aad(oscore_ctx_t *ctx,
                                cose_encrypt0_t *cose,
                                const uint8_t *oscore_option,
                                size_t oscore_option_len,
                                TSM_STR *sender_public_key,
                                uint8_t *external_aad_ptr,
                                size_t external_aad_size);

/* Creates Nonce */
void tsm_oscore_generate_nonce(cose_encrypt0_t *ptr,
                               oscore_ctx_t *ctx,
                               uint8_t *buffer,
                               uint8_t size);

/*Return 1 if OK, Error code otherwise */
uint8_t tsm_oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose);

/* Return 0 if SEQ MAX, return 1 if OK */
uint8_t tsm_oscore_increment_sender_seq(oscore_ctx_t *ctx);

/* Restore the sequence number and replay-window to the previous state. This is
 * to be used when decryption fail. */
void tsm_oscore_roll_back_seq(oscore_recipient_ctx_t *ctx);

TSM_OSCORE_CONF *tsm_oscore_conf_new(void);

void tsm_oscore_conf_free(TSM_OSCORE_CONF *oscf);

# ifdef __cplusplus
}
# endif
#endif
