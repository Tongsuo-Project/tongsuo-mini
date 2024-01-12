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
 * @file oscore.h
 * @brief An implementation of the Object Security for Constrained RESTful
 * Environments (RFC 8613).
 *
 * \author Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * major rewrite for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 * adapted for Tongsuo-mini integration
 *      K1 <dongbeiouba@gmail.com>
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

# define TSM_OSCORE_DEFAULT_REPLAY_WINDOW 32

/* Estimate your header size, especially when using Proxy-Uri. */
# define COAP_MAX_HEADER_SIZE 70

/* OSCORE error messages  (to be moved elsewhere  */
# define OSCORE_DECRYPTION_ERROR    100
# define PACKET_SERIALIZATION_ERROR 102

/* Encodes the OSCORE option value to option_buffer with length option_buf_len. Returns the written
 * length. */
size_t tsm_oscore_encode_option_value(uint8_t *option_buffer,
                                      size_t option_buf_len,
                                      cose_encrypt0_t *cose,
                                      uint8_t group,
                                      uint8_t appendix_b_2);

/* Decodes the OSCORE option value and places decoded values into the provided
 * cose structure. Returns TSM_OK if successful, error code otherwise. */
int tsm_oscore_decode_option_value(const uint8_t *option_value,
                                   size_t option_len,
                                   cose_encrypt0_t *cose);

/* Creates AAD, creates External AAD and serializes it into the complete AAD
 * structure. Returns serialized size. */
size_t tsm_oscore_prepare_aad(const uint8_t *external_aad_buffer,
                              size_t external_aad_len,
                              uint8_t *aad_buffer,
                              size_t aad_size);
/*
 * Build the CBOR for external_aad
 *
 * external_aad = bstr .cbor aad_array
 *
 * No group mode
 * aad_array = [
 *   oscore_version : uint,
 *   algorithms : [ alg_aead : int / tstr ],
 *   request_kid : bstr,
 *   request_piv : bstr,
 *   options : bstr,
 * ]
 *
 * Group mode
 * aad_array = [
 *   oscore_version : uint,
 *   algorithms : [alg_aead : int / tstr / null,
 *                 alg_signature_enc : int / tstr / null,
 *                 alg_signature : int / tstr / null,
 *                 alg_pairwise_key_agreement : int / tstr / null],
 *   request_kid : bstr,
 *   request_piv : bstr,
 *   options : bstr,
 *   request_kid_context : bstr,
 *   OSCORE_option: bstr,
 *   sender_public_key: bstr,        (initiator's key)
 *   gm_public_key: bstr / null
 * ]
 */
size_t tsm_oscore_prepare_e_aad(oscore_ctx_t *ctx,
                                cose_encrypt0_t *cose,
                                const uint8_t *oscore_option,
                                size_t oscore_option_len,
                                TSM_STR *sender_public_key,
                                uint8_t *external_aad_ptr,
                                size_t external_aad_size);

/* Creates nonce and writes to buffer with length size. */
void tsm_oscore_generate_nonce(cose_encrypt0_t *ptr,
                               oscore_ctx_t *ctx,
                               uint8_t *buffer,
                               uint8_t size);

/* Validate the sequence of sender. Returns TSM_OK if OK, error code otherwise. */
int tsm_oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose);

/* Increases the sequence of sender. Returns TSM_OK on succes, error code on error. */
int tsm_oscore_increment_sender_seq(oscore_ctx_t *ctx);
/* Restore the sequence number and replay-window to the previous state. This is
 * to be used when decryption fail. */
void tsm_oscore_roll_back_seq(oscore_recipient_ctx_t *ctx);
/* Create a OSCORE conf object which should be freed by calling tsm_oscore_conf_free() after use. */
TSM_OSCORE_CONF *tsm_oscore_conf_new(void);
/* Frees up the OSCORE conf object. */
void tsm_oscore_conf_free(TSM_OSCORE_CONF *oscf);

# ifdef __cplusplus
}
# endif
#endif
