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
 * @file oscore_cose.h
 * @brief An implementation of the CBOR Object Signing and Encryption (RFC).
 *
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted with sign1 function for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 * adapted for libcoap integration
 *      Jon Shallow <supjps-libcoap@jpshallow.com>
 * adapted for Tongsuo-mini integration
 *      K1 <dongbeiouba@gmail.com>
 */

#if !defined(TSM_OSCORE_COSE_H)
# define TSM_OSCORE_COSE_H
# pragma once

# ifdef __cplusplus
extern "C" {
# endif

# include <stdint.h>
# include <tongsuo/mem.h>

# define AES_CCM_TAG                                    16

# define COSE_ALGORITHM_ED25519_SIG_LEN                 64
# define COSE_ALGORITHM_ED25519_PRIV_KEY_LEN            32
# define COSE_ALGORITHM_ED25519_PUB_KEY_LEN             32

# define COSE_ALGORITHM_ASCON_AEAD_16_128_128_KEY_LEN   16
# define COSE_ALGORITHM_ASCON_AEAD_16_128_128_NONCE_LEN 16
# define COSE_ALGORITHM_ASCON_AEAD_16_128_128_TAG_LEN   16

# define COSE_ALGORITHM_ASCON_AEAD_64_128_128_KEY_LEN   16
# define COSE_ALGORITHM_ASCON_AEAD_64_128_128_NONCE_LEN 16
# define COSE_ALGORITHM_ASCON_AEAD_64_128_128_TAG_LEN   16

# define COSE_ALGORITHM_AES_CCM_64_64_128_KEY_LEN       16
# define COSE_ALGORITHM_AES_CCM_64_64_128_NONCE_LEN     7
# define COSE_ALGORITHM_AES_CCM_64_64_128_TAG_LEN       8

# define COSE_ALGORITHM_AES_CCM_16_64_128_KEY_LEN       16
# define COSE_ALGORITHM_AES_CCM_16_64_128_NONCE_LEN     13
# define COSE_ALGORITHM_AES_CCM_16_64_128_TAG_LEN       8

# define COSE_ALGORITHM_AES_CCM_64_128_128_KEY_LEN      16
# define COSE_ALGORITHM_AES_CCM_64_128_128_NONCE_LEN    7
# define COSE_ALGORITHM_AES_CCM_64_128_128_TAG_LEN      16

# define COSE_ALGORITHM_AES_CCM_16_128_128_KEY_LEN      16
# define COSE_ALGORITHM_AES_CCM_16_128_128_NONCE_LEN    13
# define COSE_ALGORITHM_AES_CCM_16_128_128_TAG_LEN      16

# define COSE_ALGORITHM_ES256_PRIV_KEY_LEN              24
# define COSE_ALGORITHM_ES256_PUB_KEY_LEN               32
# define COSE_ALGORITHM_ES256_SIGNATURE_LEN             64
# define COSE_ALGORITHM_ES256_HASH_LEN                  32

# define COSE_ALGORITHM_ES384_PRIV_KEY_LEN              24
# define COSE_ALGORITHM_ES384_PUB_KEY_LEN               32
# define COSE_ALGORITHM_ES384_SIGNATURE_LEN             64
# define COSE_ALGORITHM_ES384_HASH_LEN                  48

# define COSE_ALGORITHM_ES512_PRIV_KEY_LEN              24
# define COSE_ALGORITHM_ES512_PUB_KEY_LEN               32
# define COSE_ALGORITHM_ES512_SIGNATURE_LEN             64
# define COSE_ALGORITHM_ES512_HASH_LEN                  64

# define COSE_ALGORITHM_ECDH_PRIV_KEY_LEN               32
# define COSE_ALGORITHM_ECDH_PUB_KEY_LEN                32

# define COSE_ALGORITHM_SHA_512_LEN                     64
# define COSE_ALGORITHM_SHA_512_256_LEN                 32
# define COSE_ALGORITHM_SHA_256_256_LEN                 32
# define COSE_ALGORITHM_SHA_256_64_LEN                  8

# define COSE_ALGORITHM_HMAC256_64_HASH_LEN             16
# define COSE_ALGORITHM_HMAC256_256_HASH_LEN            32
# define COSE_ALGORITHM_HMAC384_384_HASH_LEN            48
# define COSE_ALGORITHM_HMAC512_512_HASH_LEN            64

/* cose algorithms */
typedef enum {
    COSE_ALGORITHM_HKDF_ASCON_HASHA = -101,
    COSE_ALGORITHM_HKDF_ASCON_HASH = -100,
    COSE_ALGORITHM_ES256K = -47, /* with ECC known as secp256k1 */
    COSE_ALGORITHM_SHA_512 = -44,
    COSE_ALGORITHM_SHA_384 = -43,
    COSE_ALGORITHM_ES512 = -36, /* with ECDSA  */
    COSE_ALGORITHM_ES384 = -35, /* with ECDSA */
    COSE_ALGORITHM_ECDH_SS_HKDF_256 = -27,
    COSE_ALGORITHM_SHA_512_256 = -17,
    COSE_ALGORITHM_SHA_256_256 = -16,
    COSE_ALGORITHM_SHA_256_64 = -15,
    COSE_ALGORITHM_SHA_1 = -14,
    COSE_ALGORITHM_HKDF_SHA_512 = -11,
    COSE_ALGORITHM_HKDF_SHA_256 = -10,
    COSE_ALGORITHM_EDDSA = -8,
    COSE_ALGORITHM_ES256 = -7,     /* with ECC known as secp256r1 */
    COSE_ALGORITHM_HMAC256_64 = 4, /* truncated to 64 bits */
    COSE_ALGORITHM_HMAC256_256 = 5,
    COSE_ALGORITHM_HMAC384_384 = 6,
    COSE_ALGORITHM_HMAC512_512 = 7,
    COSE_ALGORITHM_AES_CCM_16_64_128 = 10,
    COSE_ALGORITHM_AES_CCM_16_64_256 = 11,
    COSE_ALGORITHM_AES_CCM_64_64_128 = 12,
    COSE_ALGORITHM_AES_CCM_64_64_256 = 13,
    COSE_ALGORITHM_CHACHA20_P1035 = 24,
    COSE_ALGORITHM_AES_CCM_16_128_128 = 30,
    COSE_ALGORITHM_AES_CCM_16_128_256 = 31,
    COSE_ALGORITHM_AES_CCM_64_128_128 = 32,
    COSE_ALGORITHM_AES_CCM_64_128_256 = 33,
    COSE_ALGORITHM_ASCON_AEAD_16_128_128 = 40,
    COSE_ALGORITHM_ASCON_AEAD_64_128_128 = 41,
    COSE_ALGORITHM_HMAC_ASCON_HMAC = 100,
    COSE_ALGORITHM_HMAC_ASCON_HMACA = 100,
} cose_alg_t;

/* cose HKDF specific algorithms */
typedef enum {
    COSE_HKDF_ALG_HKDF_ASCON_HASHA = -101,
    COSE_HKDF_ALG_HKDF_ASCON_HASH = -100,
    COSE_HKDF_ALG_HKDF_SHA_512 = -11,
    COSE_HKDF_ALG_HKDF_SHA_256 = -10,
} cose_hkdf_alg_t;

/* Get algorithm name by id. The name is written to buffer with the max length buflen. The buffer is
 * returned. */
const char *tsm_cose_get_alg_name(cose_alg_t id, char *buffer, size_t buflen);
/* Returns the algorithm id of name. */
cose_alg_t tsm_cose_get_alg_id(const char *name);
/* Get hkdf algorithm name by id. The name is written to buffer with the max length buflen. The
 * buffer is returned. */
const char *tsm_cose_get_hkdf_alg_name(cose_hkdf_alg_t id, char *buffer, size_t buflen);
/* Retrives HMAC algorithm from HKDF. Returns TSM_OK means success, others mean failure. */
int tsm_cose_get_hmac_alg_for_hkdf(cose_hkdf_alg_t hkdf_alg, int *hmac_alg);
/* Returns tag length belonging to cose algorithm. */
size_t tsm_cose_tag_len(cose_alg_t cose_alg);
/* Returns hash length belonging to cose algorithm. */
size_t tsm_cose_hash_len(cose_alg_t cose_alg);
/* Returns nonce length belonging to cose algorithm. */
size_t tsm_cose_nonce_len(cose_alg_t cose_alg);
/* Returns key length belonging to cose algorithm */
size_t tsm_cose_key_len(cose_alg_t cose_alg);

/* COSE Encrypt0 Struct */
typedef struct cose_encrypt0_s {
    cose_alg_t alg;
    TSM_STR key;
    uint8_t partial_iv_data[8];
    /* partial_iv.s will point back to partial_iv_data if set */
    TSM_STR partial_iv;
    TSM_STR key_id;
    TSM_STR kid_context;
    TSM_STR oscore_option;
    TSM_STR nonce;
    TSM_STR external_aad;
    TSM_STR aad;
    TSM_STR plaintext;
    TSM_STR ciphertext;
} cose_encrypt0_t;

/* Initiate a new COSE Encrypt0 object. */
void tsm_cose_encrypt0_init(cose_encrypt0_t *ptr);
/* Sets algorithm to COSE Encrypt0 object. */
void tsm_cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg);
/* Sets plain text at buffer with length size to COSE Encrypt0 object. */
void tsm_cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);
/* Sets cipher text at buffer with length size to COSE Encrypt0 object. */
void tsm_cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr, uint8_t *buffer, size_t size);
/* Sets partial iv with length length to COSE Encrypt0 object. */
void tsm_cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, const uint8_t *partial_iv,
                                      size_t length);
/* Sets key id with length length to COSE Encrypt0 object. */
void tsm_cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, const uint8_t *key_id, size_t length);
/* Gets key id of COSE Encrypt0 object. Return length of key id. */
size_t tsm_cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, const uint8_t **buffer);
/* Sets external aad with length length to COSE Encrypt0 object. */
void tsm_cose_encrypt0_set_external_aad(cose_encrypt0_t *ptr, const uint8_t *external_aad,
                                        size_t length);
/* Sets aad with length length to COSE Encrypt0 object. */
void tsm_cose_encrypt0_set_aad(cose_encrypt0_t *ptr, const uint8_t *aad, size_t length);
/* Gets key id context of COSE Encrypt0 object. Return length of key id context. */
size_t tsm_cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, const uint8_t **buffer);
/* Sets key id context with length length to COSE Encrypt0 object. */
void tsm_cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, const uint8_t *kid_context,
                                       size_t length);
/* Sets key with length length to COSE Encrypt0 object. Returns TSM_OK if successfull, other error
 * code if key is of incorrect length. */
int tsm_cose_encrypt0_set_key(cose_encrypt0_t *ptr, const uint8_t *key, size_t length);
/* Sets nonce with length length to COSE Encrypt0 object. */
void tsm_cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, const uint8_t *nonce, size_t length);
/* Encrypts COSE Encrypt0 object and writes to ciphertext_buffer with the max length ciphertext_len.
 * Returns actual length of cipher text if successful, otherwise returns a negative integer. */
int tsm_cose_encrypt0_encrypt(cose_encrypt0_t *ptr, uint8_t *ciphertext_buffer,
                              size_t ciphertext_len);
/* Decrypts COSE Encrypt0 object and writes to plaintext_buffer with the max length plaintext_len.
 * Returns actual length of plain text if successful, otherwise returns a negative integer. */
int tsm_cose_encrypt0_decrypt(cose_encrypt0_t *ptr, uint8_t *plaintext_buffer,
                              size_t plaintext_len);

# ifdef __cplusplus
}
# endif
#endif
