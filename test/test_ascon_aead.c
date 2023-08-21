/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <string.h>
#include <tongsuo/ascon.h>
#include "internal/mem.h"
#include "test.h"

static int scheme;
static char *hex_key;
static char *hex_nonce;
static char *hex_ad;
static char *hex_plaintext;
static char *hex_ciphertext;

int test_ascon_aead_encrypt(void)
{
    unsigned char *key = tsm_hex2buf(hex_key);
    unsigned char *nonce = tsm_hex2buf(hex_nonce);
    unsigned char *ad = tsm_hex2buf(hex_ad);
    unsigned char *plaintext = tsm_hex2buf(hex_plaintext);
    unsigned char *ciphertext = tsm_hex2buf(hex_ciphertext);
    unsigned char *buf = NULL;
    int buflen;
    int plaintext_len = 0;

    if (plaintext != NULL)
        plaintext_len = strlen(hex_plaintext) / 2;

    buflen = plaintext_len + TSM_ASCON_AEAD_TAG_LEN;
    buf = tsm_alloc(buflen);
    ASSERT_OK(tsm_ascon_aead_oneshot(scheme, key, nonce, ad, ad == NULL ? 0 : strlen(hex_ad) / 2,
                                     plaintext, plaintext_len, buf, &buflen,
                                     TSM_CIPH_FLAG_ENCRYPT));

    ASSERT(buflen == plaintext_len + TSM_ASCON_AEAD_TAG_LEN);
    ASSERT(memcmp(buf, ciphertext, buflen) == 0);

    if (buf)
        tsm_free(buf);
    if (key)
        tsm_free(key);
    if (nonce)
        tsm_free(nonce);
    if (ad)
        tsm_free(ad);
    if (plaintext)
        tsm_free(plaintext);
    if (ciphertext)
        tsm_free(ciphertext);

    return 0;
}

int test_ascon_aead_decrypt(void)
{
    unsigned char *key = tsm_hex2buf(hex_key);
    unsigned char *nonce = tsm_hex2buf(hex_nonce);
    unsigned char *ad = tsm_hex2buf(hex_ad);
    unsigned char *plaintext = tsm_hex2buf(hex_plaintext);
    unsigned char *ciphertext = tsm_hex2buf(hex_ciphertext);
    unsigned char *buf = NULL;
    int buflen;
    int plaintext_len = 0;

    if (plaintext != NULL)
        plaintext_len = strlen(hex_plaintext) / 2;

    buflen = plaintext_len;
    buf = tsm_alloc(buflen);

    ASSERT_OK(tsm_ascon_aead_oneshot(scheme, key, nonce, ad, ad == NULL ? 0 : strlen(hex_ad) / 2,
                                     ciphertext, strlen(hex_ciphertext) / 2, buf, &buflen,
                                     TSM_CIPH_FLAG_DECRYPT));

    ASSERT(buflen == plaintext_len);
    ASSERT(memcmp(buf, plaintext, buflen) == 0);

    if (buf)
        tsm_free(buf);
    if (key)
        tsm_free(key);
    if (nonce)
        tsm_free(nonce);
    if (ad)
        tsm_free(ad);
    if (plaintext)
        tsm_free(plaintext);
    if (ciphertext)
        tsm_free(ciphertext);

    return 0;
}

int main(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            if (i + 1 >= argc)
                break;

            if (argv[i + 1][0] == '-')
                continue;

            if (strcmp(argv[i], "-scheme") == 0) {
                if (strcmp(argv[i + 1], "ascon128") == 0) {
                    scheme = TSM_ASCON_AEAD_128;
                } else if (strcmp(argv[i + 1], "ascon128a") == 0) {
                    scheme = TSM_ASCON_AEAD_128A;
                } else {
                    fprintf(stderr, "unknown scheme\n");
                    return 1;
                }
                i++;
            } else if (strcmp(argv[i], "-key") == 0) {
                hex_key = argv[i + 1];
                i++;
            } else if (strcmp(argv[i], "-nonce") == 0) {
                hex_nonce = argv[i + 1];
                i++;
            } else if (strcmp(argv[i], "-ad") == 0) {
                hex_ad = argv[i + 1];
                i++;
            } else if (strcmp(argv[i], "-pt") == 0) {
                hex_plaintext = argv[i + 1];
                i++;
            } else if (strcmp(argv[i], "-ct") == 0) {
                hex_ciphertext = argv[i + 1];
                i++;
            }
        }
    }

    TEST(test_ascon_aead_encrypt);
    TEST(test_ascon_aead_decrypt);
    return 0;
}
