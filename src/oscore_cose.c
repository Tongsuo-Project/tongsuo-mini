/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include "internal/log.h"
#include <tongsuo/minisuo.h>
#include <tongsuo/ascon.h>
#include <tongsuo/hmac.h>
#include <tongsuo/oscore_cbor.h>
#include <tongsuo/oscore_cose.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct cose_alg_desc {
    const char *name;
    cose_alg_t id;
};

static struct cose_alg_desc alg_mapping[] = {
    {"ES256K", COSE_ALGORITHM_ES256K},
    {"SHA-512", COSE_ALGORITHM_SHA_512},
    {"SHA-384", COSE_ALGORITHM_SHA_384},
    {"ES512", COSE_ALGORITHM_ES512},
    {"ES384", COSE_ALGORITHM_ES384},
    {"ECDH-SS + HKDF-256", COSE_ALGORITHM_ECDH_SS_HKDF_256},
    {"SHA-512/256", COSE_ALGORITHM_SHA_512_256},
    {"SHA-256", COSE_ALGORITHM_SHA_256_256},
    {"SHA-256/64", COSE_ALGORITHM_SHA_256_64},
    {"SHA-1", COSE_ALGORITHM_SHA_1},
    {"direct+HKDF-SHA-512", COSE_ALGORITHM_HKDF_SHA_512},
    {"direct+HKDF-SHA-256", COSE_ALGORITHM_HKDF_SHA_256},
    {"direct+HKDF-ASCON-HASH", COSE_ALGORITHM_HKDF_ASCON_HASH},
    {"direct+HKDF-ASCON-HASHA", COSE_ALGORITHM_HKDF_ASCON_HASHA},
    {"EdDSA", COSE_ALGORITHM_EDDSA},
    {"ES256", COSE_ALGORITHM_ES256},
    {"HMAC 256/64", COSE_ALGORITHM_HMAC256_64},
    {"HMAC 256/256", COSE_ALGORITHM_HMAC256_256},
    {"HMAC 384/384", COSE_ALGORITHM_HMAC384_384},
    {"HMAC 512/512", COSE_ALGORITHM_HMAC512_512},
    {"AES-CCM-16-64-128", COSE_ALGORITHM_AES_CCM_16_64_128},
    {"AES-CCM-16-64-256", COSE_ALGORITHM_AES_CCM_16_64_256},
    {"AES-CCM-64-64-128", COSE_ALGORITHM_AES_CCM_64_64_128},
    {"AES-CCM-64-64-256", COSE_ALGORITHM_AES_CCM_64_64_256},
    {"ChaCha20/Poly1305", COSE_ALGORITHM_CHACHA20_P1035},
    {"AES-CCM-16-128-128", COSE_ALGORITHM_AES_CCM_16_128_128},
    {"AES-CCM-16-128-256", COSE_ALGORITHM_AES_CCM_16_128_256},
    {"AES-CCM-64-128-128", COSE_ALGORITHM_AES_CCM_64_128_128},
    {"AES-CCM-64-128-256", COSE_ALGORITHM_AES_CCM_64_128_256},
};

const char *tsm_cose_get_alg_name(cose_alg_t id, char *buffer, size_t buflen)
{
    for (size_t i = 0; i < sizeof(alg_mapping) / sizeof(alg_mapping[0]); i++) {
        if (id == alg_mapping[i].id) {
            snprintf(buffer, buflen, "%s (%d)", alg_mapping[i].name, id);
            return buffer;
        }
    }
    snprintf(buffer, buflen, "alg Fix me (%d)", id);
    return buffer;
}

cose_alg_t tsm_cose_get_alg_id(const char *name)
{
    for (size_t i = 0; i < sizeof(alg_mapping) / sizeof(alg_mapping[0]); i++) {
        if (strcmp(name, alg_mapping[i].name) == 0)
            return alg_mapping[i].id;
    }
    return 0;
}

struct cose_hkdf_alg_desc {
    const char *name;
    cose_hkdf_alg_t id;
};

static struct cose_hkdf_alg_desc hkdf_alg_mapping[] = {
    /*
        {"direct+HKDF-SHA-512", COSE_HKDF_ALG_HKDF_SHA_512},
        {"direct+HKDF-SHA-256", COSE_HKDF_ALG_HKDF_SHA_256},
    */
    {"direct+HKDF-ASCON-HASH", COSE_HKDF_ALG_HKDF_ASCON_HASH},
    {"direct+HKDF-ASCON-HASHA", COSE_HKDF_ALG_HKDF_ASCON_HASHA},
};

const char *tsm_cose_get_hkdf_alg_name(cose_hkdf_alg_t id, char *buffer, size_t buflen)
{
    for (size_t i = 0; i < sizeof(hkdf_alg_mapping) / sizeof(hkdf_alg_mapping[0]); i++) {
        if (id == hkdf_alg_mapping[i].id) {
            snprintf(buffer, buflen, "%s (%d)", hkdf_alg_mapping[i].name, id);
            return buffer;
        }
    }
    snprintf(buffer, buflen, "hkdf_alg Fix me (%d)", id);
    return buffer;
}

/*
 * The struct hmac_algs and the function tsm_cose_get_hmac_alg_for_hkdf() are
 * used to determine which hmac type to use for the appropriate hkdf
 */
static struct hkdf_hmac_algs {
    cose_hkdf_alg_t hkdf_alg;
    int hmac_alg;
} hkdf_hmacs[] = {
    /*
    {COSE_HKDF_ALG_HKDF_SHA_256, COSE_HMAC_ALG_HMAC256_256},
    {COSE_HKDF_ALG_HKDF_SHA_512, COSE_HMAC_ALG_HMAC512_512},
    */
    {COSE_HKDF_ALG_HKDF_ASCON_HASH, TSM_HASH_ASCON_HASH},
    {COSE_HKDF_ALG_HKDF_ASCON_HASHA, TSM_HASH_ASCON_HASHA},
};

int tsm_cose_get_hmac_alg_for_hkdf(cose_hkdf_alg_t hkdf_alg, int *hmac_alg)
{
    size_t idx;

    for (idx = 0; idx < sizeof(hkdf_hmacs) / sizeof(struct hkdf_hmac_algs); idx++) {
        if (hkdf_hmacs[idx].hkdf_alg == hkdf_alg) {
            *hmac_alg = hkdf_hmacs[idx].hmac_alg;
            return TSM_OK;
        }
    }
    LOGD("tsm_cose_get_hmac_alg_for_hkdf: COSE HKDF %d not supported\n", hkdf_alg);
    return TSM_ERR_ALGORITHM_NOT_SUPPORTED;
}

/* return tag length belonging to cose algorithm */
size_t tsm_cose_tag_len(cose_alg_t cose_alg)
{
    switch ((int)cose_alg) {
    case COSE_ALGORITHM_AES_CCM_16_64_128:
        return COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN;
    case COSE_ALGORITHM_AES_CCM_64_64_128:
        return COSE_ALGORITHM_AES_CCM_64_64_128_TAG_LEN;
    case COSE_ALGORITHM_AES_CCM_16_128_128:
        return COSE_ALGORITHM_AES_CCM_16_128_128_TAG_LEN;
    case COSE_ALGORITHM_AES_CCM_64_128_128:
        return COSE_ALGORITHM_AES_CCM_64_128_128_TAG_LEN;
    case COSE_ALGORITHM_ASCON_AEAD_16_128_128:
        return COSE_ALGORITHM_ASCON_AEAD_16_128_128_TAG_LEN;
    case COSE_ALGORITHM_ASCON_AEAD_64_128_128:
        return COSE_ALGORITHM_ASCON_AEAD_64_128_128_TAG_LEN;
    default:
        return 0;
    }
}

/* return hash length belonging to cose algorithm */
size_t tsm_cose_hash_len(cose_alg_t cose_alg)
{
    switch ((int)cose_alg) {
    case COSE_ALGORITHM_ES256:
        return COSE_ALGORITHM_HMAC256_256_HASH_LEN;
    case COSE_ALGORITHM_ES512:
        return COSE_ALGORITHM_ES512_HASH_LEN;
    case COSE_ALGORITHM_ES384:
        return COSE_ALGORITHM_ES384_HASH_LEN;
    case COSE_ALGORITHM_HMAC256_64:
        return COSE_ALGORITHM_HMAC256_64_HASH_LEN;
    case COSE_ALGORITHM_HMAC256_256:
        return COSE_ALGORITHM_HMAC256_256_HASH_LEN;
    case COSE_ALGORITHM_HMAC384_384:
        return COSE_ALGORITHM_HMAC384_384_HASH_LEN;
    case COSE_ALGORITHM_HMAC512_512:
        return COSE_ALGORITHM_HMAC512_512_HASH_LEN;
    case COSE_ALGORITHM_SHA_256_64:
        return COSE_ALGORITHM_SHA_256_64_LEN;
    case COSE_ALGORITHM_SHA_256_256:
        return COSE_ALGORITHM_SHA_256_256_LEN;
    case COSE_ALGORITHM_SHA_512_256:
        return COSE_ALGORITHM_SHA_512_256_LEN;
    case COSE_ALGORITHM_SHA_512:
        return COSE_ALGORITHM_SHA_512_LEN;
    default:
        return 0;
    }
}

/* return nonce length belonging to cose algorithm */
size_t tsm_cose_nonce_len(cose_alg_t cose_alg)
{
    switch ((int)cose_alg) {
    case COSE_ALGORITHM_AES_CCM_16_64_128:
        return COSE_ALGORITHM_AES_CCM_16_64_128_NONCE_LEN;
    case COSE_ALGORITHM_AES_CCM_64_64_128:
        return COSE_ALGORITHM_AES_CCM_64_64_128_NONCE_LEN;
    case COSE_ALGORITHM_AES_CCM_16_128_128:
        return COSE_ALGORITHM_AES_CCM_16_128_128_NONCE_LEN;
    case COSE_ALGORITHM_AES_CCM_64_128_128:
        return COSE_ALGORITHM_AES_CCM_64_128_128_NONCE_LEN;
    case COSE_ALGORITHM_ASCON_AEAD_16_128_128:
        return COSE_ALGORITHM_ASCON_AEAD_16_128_128_NONCE_LEN;
    case COSE_ALGORITHM_ASCON_AEAD_64_128_128:
        return COSE_ALGORITHM_ASCON_AEAD_64_128_128_NONCE_LEN;
    default:
        return -1;
    }
}

/* return key length belonging to cose algorithm */
size_t tsm_cose_key_len(cose_alg_t cose_alg)
{
    switch ((int)cose_alg) {
    case COSE_ALGORITHM_AES_CCM_16_64_128:
        return COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN;
    case COSE_ALGORITHM_AES_CCM_64_64_128:
        return COSE_ALGORITHM_AES_CCM_64_64_128_KEY_LEN;
    case COSE_ALGORITHM_AES_CCM_16_128_128:
        return COSE_ALGORITHM_AES_CCM_16_128_128_KEY_LEN;
    case COSE_ALGORITHM_AES_CCM_64_128_128:
        return COSE_ALGORITHM_AES_CCM_64_128_128_KEY_LEN;
    case COSE_ALGORITHM_ASCON_AEAD_16_128_128:
        return COSE_ALGORITHM_ASCON_AEAD_16_128_128_KEY_LEN;
    case COSE_ALGORITHM_ASCON_AEAD_64_128_128:
        return COSE_ALGORITHM_ASCON_AEAD_64_128_128_KEY_LEN;
    default:
        return -1;
    }
}

/* Initiate a new COSE Encrypt0 object. */
void tsm_cose_encrypt0_init(cose_encrypt0_t *ptr)
{
    memset(ptr, 0, sizeof(cose_encrypt0_t));
}

void tsm_cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg)
{
    ptr->alg = alg;
}

void tsm_cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size)
{
    ptr->ciphertext.s = buffer;
    ptr->ciphertext.length = size;
}

void tsm_cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size)
{
    ptr->plaintext.s = buffer;
    ptr->plaintext.length = size;
}

void tsm_cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, const uint8_t *partial_iv,
                                      size_t length)
{
    if (partial_iv == NULL || length == 0) {
        ptr->partial_iv.s = NULL;
        ptr->partial_iv.length = 0;
    } else {
        if (length > (int)sizeof(ptr->partial_iv_data))
            length = sizeof(ptr->partial_iv_data);
        memcpy(ptr->partial_iv_data, partial_iv, length);
        ptr->partial_iv.s = ptr->partial_iv_data;
        ptr->partial_iv.length = length;
    }
}

void tsm_cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, const uint8_t *key_id, size_t length)
{
    if (key_id) {
        ptr->key_id.s = key_id;
        ptr->key_id.length = length;
    } else {
        ptr->key_id.length = 0;
        ptr->key_id.s = NULL;
    }
}
/* Return length */
size_t tsm_cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, const uint8_t **buffer)
{
    *buffer = ptr->key_id.s;
    return ptr->key_id.length;
}

size_t tsm_cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, const uint8_t **buffer)
{
    *buffer = ptr->kid_context.s;
    return ptr->kid_context.length;
}

void tsm_cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, const uint8_t *kid_context,
                                       size_t length)
{
    if (kid_context) {
        ptr->kid_context.s = kid_context;
        ptr->kid_context.length = length;
    } else {
        ptr->kid_context.length = 0;
        ptr->kid_context.s = NULL;
    }
}

void tsm_cose_encrypt0_set_external_aad(cose_encrypt0_t *ptr, const uint8_t *external_aad,
                                        size_t length)
{
    if (external_aad) {
        ptr->external_aad.s = external_aad;
        ptr->external_aad.length = length;
    } else {
        ptr->external_aad.length = 0;
        ptr->external_aad.s = NULL;
    }
}

void tsm_cose_encrypt0_set_aad(cose_encrypt0_t *ptr, const uint8_t *aad, size_t length)
{
    if (aad) {
        ptr->aad.s = aad;
        ptr->aad.length = length;
    } else {
        ptr->aad.length = 0;
        ptr->aad.s = NULL;
    }
}

int tsm_cose_encrypt0_set_key(cose_encrypt0_t *ptr, const uint8_t *key, size_t length)
{
    if (key == NULL || length != 16) {
        return TSM_FAILED;
    }

    ptr->key.s = key;
    ptr->key.length = length;
    return TSM_OK;
}

void tsm_cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, const uint8_t *nonce, size_t length)
{
    if (nonce) {
        ptr->nonce.s = nonce;
        ptr->nonce.length = length;
    } else {
        ptr->nonce.length = 0;
        ptr->nonce.s = NULL;
    }
}

int tsm_cose_encrypt0_encrypt(cose_encrypt0_t *ptr, uint8_t *ciphertext_buffer,
                              size_t ciphertext_len)
{
    size_t tag_len = tsm_cose_tag_len(ptr->alg);
    size_t max_result_len = ptr->plaintext.length + tag_len;

    if (ptr->key.s == NULL || ptr->key.length != (size_t)tsm_cose_key_len(ptr->alg)) {
        return -1;
    }
    if (ptr->nonce.s == NULL || ptr->nonce.length != (size_t)tsm_cose_nonce_len(ptr->alg)) {
        return -2;
    }
    if (ptr->aad.s == NULL || ptr->aad.length == 0) {
        return -3;
    }
    if (ptr->plaintext.s == NULL || (ptr->plaintext.length + tag_len) > ciphertext_len) {
        return -4;
    }

    if (ptr->alg == COSE_ALGORITHM_ASCON_AEAD_16_128_128
        || ptr->alg == COSE_ALGORITHM_ASCON_AEAD_64_128_128) {
        if (tsm_ascon_aead_oneshot(TSM_ASCON_AEAD_128, ptr->key.s, ptr->nonce.s, ptr->aad.s,
                                   ptr->aad.length, ptr->plaintext.s, ptr->plaintext.length,
                                   ciphertext_buffer, &max_result_len, TSM_CIPH_FLAG_ENCRYPT)
            != TSM_OK) {
            return -5;
        }
    } else {
        // unknown algorithm
        return -6;
    }

    return (int)max_result_len;
}

int tsm_cose_encrypt0_decrypt(cose_encrypt0_t *ptr, uint8_t *plaintext_buffer, size_t plaintext_len)
{
    int ret_len = 0;
    size_t tag_len = tsm_cose_tag_len(ptr->alg);
    size_t max_result_len = ptr->ciphertext.length - tag_len;

    if (ptr->key.s == NULL || ptr->key.length != (size_t)tsm_cose_key_len(ptr->alg)) {
        return -1;
    }
    if (ptr->nonce.s == NULL || ptr->nonce.length != (size_t)tsm_cose_nonce_len(ptr->alg)) {
        return -2;
    }
    if (ptr->aad.s == NULL || ptr->aad.length == 0) {
        return -3;
    }
    if (ptr->ciphertext.s == NULL || ptr->ciphertext.length > (plaintext_len + tag_len)) {
        return -4;
    }

    if (ptr->alg == COSE_ALGORITHM_ASCON_AEAD_16_128_128
        || ptr->alg == COSE_ALGORITHM_ASCON_AEAD_64_128_128) {
        if (tsm_ascon_aead_oneshot(TSM_ASCON_AEAD_128, ptr->key.s, ptr->nonce.s, ptr->aad.s,
                                   ptr->aad.length, ptr->ciphertext.s, ptr->ciphertext.length,
                                   plaintext_buffer, &max_result_len, TSM_CIPH_FLAG_DECRYPT)
            != TSM_OK) {
            return -5;
        }
    } else {
        // unknown algorithm
        return -6;
    }
    ret_len = (int)max_result_len;
    return ret_len;
}
