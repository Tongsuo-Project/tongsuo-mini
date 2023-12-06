/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include "test.h"
#include <stdlib.h>
#include <string.h>
#include <tongsuo/oscore.h>
#include <tongsuo/oscore_cose.h>
#include <tongsuo/oscore_context.h>

/* Key Derivation with Master Salt, Client */
static int test_oscore_1_1(void)
{
    const uint8_t master_secret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    const uint8_t master_salt[] = {
        0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40,
    };
    const uint8_t recipient_id[] = {0x01};
    const uint8_t sender_key[] = {
        0x51, 0x8f, 0xcd, 0xfa, 0x81, 0x16, 0x57, 0x54,
        0xcb, 0xe8, 0x75, 0xbc, 0x56, 0x2d, 0x1f, 0x2f,
    };
    const uint8_t recipient_key[] = {
        0x8b, 0xcf, 0xdd, 0x5b, 0xb1, 0x3e, 0xb7, 0xa4,
        0x3f, 0x49, 0x1b, 0xc0, 0x8f, 0x9b, 0x4e, 0x4f,
    };
    const uint8_t common_iv[] = {
        0x2c, 0xe6, 0x12, 0x95, 0xff, 0x90, 0x99, 0x44,
        0xe2, 0x71, 0xd4, 0x55, 0xbd, 0xad, 0x46, 0x6c,
    };
    const uint8_t sender_nonce[] = {
        0x2c, 0xe6, 0x12, 0x95, 0xff, 0x90, 0x99, 0x44,
        0xe2, 0x71, 0xd4, 0x55, 0xbd, 0xad, 0x46, 0x6c,
    };
    const uint8_t recipient_nonce[] = {
        0x2d, 0xe6, 0x12, 0x95, 0xff, 0x90, 0x99, 0x44,
        0xe2, 0x71, 0xd5, 0x55, 0xbd, 0xad, 0x46, 0x6c,
    };
    cose_encrypt0_t cose[1];
    uint8_t nonce_buffer[16];
    TSM_OSCORE_CONF *oscf = NULL;
    oscore_ctx_t *osc_ctx = NULL;

    oscf = tsm_oscore_conf_new();
    ASSERT(oscf);
    oscf->master_secret = tsm_str_new(master_secret, sizeof(master_secret));
    oscf->master_salt = tsm_str_new(master_salt, sizeof(master_salt));
    oscf->sender_id = NULL;
    oscf->recipient_id = tsm_alloc(sizeof(TSM_STR) * oscf->recipient_id_count + 1);
    oscf->recipient_id[oscf->recipient_id_count++] =
        tsm_str_new(recipient_id, sizeof(recipient_id));

    osc_ctx = tsm_oscore_ctx_new(oscf);
    ASSERT(osc_ctx);

    ASSERT_0(memcmp(sender_key, osc_ctx->sender_context->sender_key->s, sizeof(sender_key)));
    ASSERT_0(
        memcmp(recipient_key, osc_ctx->recipient_chain->recipient_key->s, sizeof(recipient_key)));
    ASSERT_0(memcmp(common_iv, osc_ctx->common_iv->s, sizeof(common_iv)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, osc_ctx->recipient_chain->recipient_id->s,
                                 osc_ctx->recipient_chain->recipient_id->length);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(recipient_nonce, nonce_buffer, sizeof(recipient_nonce)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, NULL, 0);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(sender_nonce, nonce_buffer, sizeof(sender_nonce)));

    tsm_oscore_ctx_free(osc_ctx);
    tsm_oscore_conf_free(oscf);

    return 0;
}

/* Key Derivation with Master Salt, Server */
static int test_oscore_1_2(void)
{
    const uint8_t master_secret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    const uint8_t master_salt[] = {
        0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40,
    };
    const uint8_t sender_id[] = {0x01};
    const uint8_t sender_key[] = {
        0x8b, 0xcf, 0xdd, 0x5b, 0xb1, 0x3e, 0xb7, 0xa4,
        0x3f, 0x49, 0x1b, 0xc0, 0x8f, 0x9b, 0x4e, 0x4f,
    };
    const uint8_t recipient_key[] = {
        0x51, 0x8f, 0xcd, 0xfa, 0x81, 0x16, 0x57, 0x54,
        0xcb, 0xe8, 0x75, 0xbc, 0x56, 0x2d, 0x1f, 0x2f,
    };
    const uint8_t common_iv[] = {
        0x2c, 0xe6, 0x12, 0x95, 0xff, 0x90, 0x99, 0x44,
        0xe2, 0x71, 0xd4, 0x55, 0xbd, 0xad, 0x46, 0x6c,
    };
    const uint8_t sender_nonce[] = {
        0x2d, 0xe6, 0x12, 0x95, 0xff, 0x90, 0x99, 0x44,
        0xe2, 0x71, 0xd5, 0x55, 0xbd, 0xad, 0x46, 0x6c,
    };
    const uint8_t recipient_nonce[] = {
        0x2c, 0xe6, 0x12, 0x95, 0xff, 0x90, 0x99, 0x44,
        0xe2, 0x71, 0xd4, 0x55, 0xbd, 0xad, 0x46, 0x6c,
    };
    cose_encrypt0_t cose[1];
    uint8_t nonce_buffer[16];
    TSM_OSCORE_CONF *oscf = NULL;
    oscore_ctx_t *osc_ctx = NULL;

    oscf = tsm_oscore_conf_new();
    ASSERT(oscf);
    oscf->master_secret = tsm_str_new(master_secret, sizeof(master_secret));
    oscf->master_salt = tsm_str_new(master_salt, sizeof(master_salt));
    oscf->sender_id = tsm_str_new(sender_id, sizeof(sender_id));
    oscf->recipient_id = tsm_calloc(sizeof(TSM_STR) * oscf->recipient_id_count + 1);
    oscf->recipient_id[oscf->recipient_id_count++] = tsm_str_new(NULL, 0);

    osc_ctx = tsm_oscore_ctx_new(oscf);
    ASSERT(osc_ctx);

    ASSERT_0(memcmp(sender_key, osc_ctx->sender_context->sender_key->s, sizeof(sender_key)));
    ASSERT_0(
        memcmp(recipient_key, osc_ctx->recipient_chain->recipient_key->s, sizeof(recipient_key)));
    ASSERT_0(memcmp(common_iv, osc_ctx->common_iv->s, sizeof(common_iv)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, NULL, 0);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(recipient_nonce, nonce_buffer, sizeof(recipient_nonce)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, osc_ctx->sender_context->sender_id->s,
                                 osc_ctx->sender_context->sender_id->length);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(sender_nonce, nonce_buffer, sizeof(sender_nonce)));

    tsm_oscore_ctx_free(osc_ctx);
    tsm_oscore_conf_free(oscf);

    return 0;
}

/* Key Derivation without Master Salt, Client */
static int test_oscore_2_1(void)
{
    const uint8_t master_secret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    const uint8_t sender_id[] = {0x00};
    const uint8_t recipient_id[] = {0x01};
    const uint8_t sender_key[] = {
        0xe3, 0x1a, 0x0d, 0x51, 0x51, 0x71, 0x7a, 0x35,
        0xec, 0xf3, 0xc6, 0xa9, 0x50, 0x21, 0x6a, 0xfd,
    };
    const uint8_t recipient_key[] = {
        0x54, 0x21, 0x61, 0x7f, 0x49, 0xf0, 0xc4, 0x91,
        0x20, 0x22, 0x8d, 0x08, 0x97, 0x1c, 0xfe, 0xdb,
    };
    const uint8_t common_iv[] = {
        0x14, 0xba, 0x31, 0x53, 0x2d, 0x08, 0x18, 0x73,
        0xd7, 0x9c, 0x71, 0x2c, 0x7b, 0xa1, 0x12, 0xa8,
    };
    const uint8_t sender_nonce[] = {
        0x15, 0xba, 0x31, 0x53, 0x2d, 0x08, 0x18, 0x73,
        0xd7, 0x9c, 0x71, 0x2c, 0x7b, 0xa1, 0x12, 0xa8,
    };
    const uint8_t recipient_nonce[] = {
        0x15, 0xba, 0x31, 0x53, 0x2d, 0x08, 0x18, 0x73,
        0xd7, 0x9c, 0x70, 0x2c, 0x7b, 0xa1, 0x12, 0xa8,
    };
    cose_encrypt0_t cose[1];
    uint8_t nonce_buffer[16];
    TSM_OSCORE_CONF *oscf = NULL;
    oscore_ctx_t *osc_ctx = NULL;

    oscf = tsm_oscore_conf_new();
    ASSERT(oscf);
    oscf->master_secret = tsm_str_new(master_secret, sizeof(master_secret));
    oscf->sender_id = tsm_str_new(sender_id, sizeof(sender_id));
    oscf->recipient_id = tsm_alloc(sizeof(TSM_STR) * oscf->recipient_id_count + 1);
    oscf->recipient_id[oscf->recipient_id_count++] =
        tsm_str_new(recipient_id, sizeof(recipient_id));

    osc_ctx = tsm_oscore_ctx_new(oscf);
    ASSERT(osc_ctx);

    ASSERT_0(memcmp(sender_key, osc_ctx->sender_context->sender_key->s, sizeof(sender_key)));
    ASSERT_0(
        memcmp(recipient_key, osc_ctx->recipient_chain->recipient_key->s, sizeof(recipient_key)));
    ASSERT_0(memcmp(common_iv, osc_ctx->common_iv->s, sizeof(common_iv)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, osc_ctx->recipient_chain->recipient_id->s,
                                 osc_ctx->recipient_chain->recipient_id->length);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(recipient_nonce, nonce_buffer, sizeof(recipient_nonce)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, osc_ctx->sender_context->sender_id->s,
                                 osc_ctx->sender_context->sender_id->length);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(sender_nonce, nonce_buffer, sizeof(sender_nonce)));

    tsm_oscore_ctx_free(osc_ctx);
    tsm_oscore_conf_free(oscf);

    return 0;
}

/* Key Derivation without Master Salt, Server */
static int test_oscore_2_2(void)
{
    const uint8_t master_secret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    const uint8_t sender_id[] = {0x01};
    const uint8_t recipient_id[] = {0x00};
    const uint8_t sender_key[] = {
        0x54, 0x21, 0x61, 0x7f, 0x49, 0xf0, 0xc4, 0x91,
        0x20, 0x22, 0x8d, 0x08, 0x97, 0x1c, 0xfe, 0xdb,
    };
    const uint8_t recipient_key[] = {
        0xe3, 0x1a, 0x0d, 0x51, 0x51, 0x71, 0x7a, 0x35,
        0xec, 0xf3, 0xc6, 0xa9, 0x50, 0x21, 0x6a, 0xfd,
    };
    const uint8_t common_iv[] = {
        0x14, 0xba, 0x31, 0x53, 0x2d, 0x08, 0x18, 0x73,
        0xd7, 0x9c, 0x71, 0x2c, 0x7b, 0xa1, 0x12, 0xa8,
    };
    const uint8_t sender_nonce[] = {
        0x15, 0xba, 0x31, 0x53, 0x2d, 0x08, 0x18, 0x73,
        0xd7, 0x9c, 0x70, 0x2c, 0x7b, 0xa1, 0x12, 0xa8,
    };
    const uint8_t recipient_nonce[] = {
        0x15, 0xba, 0x31, 0x53, 0x2d, 0x08, 0x18, 0x73,
        0xd7, 0x9c, 0x71, 0x2c, 0x7b, 0xa1, 0x12, 0xa8,
    };
    cose_encrypt0_t cose[1];
    uint8_t nonce_buffer[16];
    TSM_OSCORE_CONF *oscf = NULL;
    oscore_ctx_t *osc_ctx = NULL;

    oscf = tsm_oscore_conf_new();
    ASSERT(oscf);
    oscf->master_secret = tsm_str_new(master_secret, sizeof(master_secret));
    oscf->sender_id = tsm_str_new(sender_id, sizeof(sender_id));
    oscf->recipient_id = tsm_alloc(sizeof(TSM_STR) * oscf->recipient_id_count + 1);
    oscf->recipient_id[oscf->recipient_id_count++] =
        tsm_str_new(recipient_id, sizeof(recipient_id));

    osc_ctx = tsm_oscore_ctx_new(oscf);
    ASSERT(osc_ctx);

    ASSERT_0(memcmp(sender_key, osc_ctx->sender_context->sender_key->s, sizeof(sender_key)));
    ASSERT_0(
        memcmp(recipient_key, osc_ctx->recipient_chain->recipient_key->s, sizeof(recipient_key)));
    ASSERT_0(memcmp(common_iv, osc_ctx->common_iv->s, sizeof(common_iv)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, osc_ctx->recipient_chain->recipient_id->s,
                                 osc_ctx->recipient_chain->recipient_id->length);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(recipient_nonce, nonce_buffer, sizeof(recipient_nonce)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, osc_ctx->sender_context->sender_id->s,
                                 osc_ctx->sender_context->sender_id->length);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(sender_nonce, nonce_buffer, sizeof(sender_nonce)));

    tsm_oscore_ctx_free(osc_ctx);
    tsm_oscore_conf_free(oscf);

    return 0;
}

/* Key Derivation with ID Context, Client */
static int test_oscore_3_1(void)
{
    const uint8_t master_secret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    const uint8_t master_salt[] = {
        0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40,
    };
    const uint8_t id_context[] = {
        0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3,
    };
    const uint8_t recipient_id[] = {0x01};
    const uint8_t sender_key[] = {
        0x3b, 0x21, 0xbc, 0x99, 0xd5, 0x5f, 0x23, 0x2c,
        0xf9, 0x06, 0x5a, 0xdd, 0xcb, 0xdc, 0x5b, 0xed,
    };
    const uint8_t recipient_key[] = {
        0xeb, 0x3e, 0xd3, 0x43, 0xe6, 0xb7, 0xd1, 0xc8,
        0xb9, 0x44, 0x05, 0x9d, 0xd0, 0x31, 0xe2, 0x50,
    };
    const uint8_t common_iv[] = {
        0x8a, 0x4b, 0x98, 0x9f, 0xb0, 0xd7, 0x41, 0x5f,
        0x1c, 0xaf, 0x70, 0x63, 0x6c, 0xcc, 0x31, 0x81,
    };
    const uint8_t sender_nonce[] = {
        0x8a, 0x4b, 0x98, 0x9f, 0xb0, 0xd7, 0x41, 0x5f,
        0x1c, 0xaf, 0x70, 0x63, 0x6c, 0xcc, 0x31, 0x81,
    };
    const uint8_t recipient_nonce[] = {
        0x8b, 0x4b, 0x98, 0x9f, 0xb0, 0xd7, 0x41, 0x5f,
        0x1c, 0xaf, 0x71, 0x63, 0x6c, 0xcc, 0x31, 0x81,
    };
    cose_encrypt0_t cose[1];
    uint8_t nonce_buffer[16];
    TSM_OSCORE_CONF *oscf = NULL;
    oscore_ctx_t *osc_ctx = NULL;

    oscf = tsm_oscore_conf_new();
    ASSERT(oscf);
    oscf->master_secret = tsm_str_new(master_secret, sizeof(master_secret));
    oscf->master_salt = tsm_str_new(master_salt, sizeof(master_salt));
    oscf->id_context = tsm_str_new(id_context, sizeof(id_context));
    oscf->sender_id = tsm_str_new(NULL, 0);
    oscf->recipient_id = tsm_alloc(sizeof(TSM_STR) * oscf->recipient_id_count + 1);
    oscf->recipient_id[oscf->recipient_id_count++] =
        tsm_str_new(recipient_id, sizeof(recipient_id));

    osc_ctx = tsm_oscore_ctx_new(oscf);
    ASSERT(osc_ctx);

    ASSERT_0(memcmp(sender_key, osc_ctx->sender_context->sender_key->s, sizeof(sender_key)));
    ASSERT_0(
        memcmp(recipient_key, osc_ctx->recipient_chain->recipient_key->s, sizeof(recipient_key)));
    ASSERT_0(memcmp(common_iv, osc_ctx->common_iv->s, sizeof(common_iv)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, osc_ctx->recipient_chain->recipient_id->s,
                                 osc_ctx->recipient_chain->recipient_id->length);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(recipient_nonce, nonce_buffer, sizeof(recipient_nonce)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, NULL, 0);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(sender_nonce, nonce_buffer, sizeof(sender_nonce)));

    tsm_oscore_ctx_free(osc_ctx);
    tsm_oscore_conf_free(oscf);

    return 0;
}

/* Key Derivation with ID Context, Server */
static int test_oscore_3_2(void)
{
    const uint8_t master_secret[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    };
    const uint8_t master_salt[] = {
        0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40,
    };
    const uint8_t id_context[] = {
        0x37, 0xcb, 0xf3, 0x21, 0x00, 0x17, 0xa2, 0xd3,
    };
    const uint8_t sender_id[] = {0x01};
    const uint8_t sender_key[] = {
        0xeb, 0x3e, 0xd3, 0x43, 0xe6, 0xb7, 0xd1, 0xc8,
        0xb9, 0x44, 0x05, 0x9d, 0xd0, 0x31, 0xe2, 0x50,
    };
    const uint8_t recipient_key[] = {
        0x3b, 0x21, 0xbc, 0x99, 0xd5, 0x5f, 0x23, 0x2c,
        0xf9, 0x06, 0x5a, 0xdd, 0xcb, 0xdc, 0x5b, 0xed,
    };
    const uint8_t common_iv[] = {
        0x8a, 0x4b, 0x98, 0x9f, 0xb0, 0xd7, 0x41, 0x5f,
        0x1c, 0xaf, 0x70, 0x63, 0x6c, 0xcc, 0x31, 0x81,
    };
    const uint8_t sender_nonce[] = {
        0x8b, 0x4b, 0x98, 0x9f, 0xb0, 0xd7, 0x41, 0x5f,
        0x1c, 0xaf, 0x71, 0x63, 0x6c, 0xcc, 0x31, 0x81,
    };
    const uint8_t recipient_nonce[] = {
        0x8a, 0x4b, 0x98, 0x9f, 0xb0, 0xd7, 0x41, 0x5f,
        0x1c, 0xaf, 0x70, 0x63, 0x6c, 0xcc, 0x31, 0x81,
    };
    cose_encrypt0_t cose[1];
    uint8_t nonce_buffer[16];
    TSM_OSCORE_CONF *oscf = NULL;
    oscore_ctx_t *osc_ctx = NULL;

    oscf = tsm_oscore_conf_new();
    ASSERT(oscf);
    oscf->master_secret = tsm_str_new(master_secret, sizeof(master_secret));
    oscf->master_salt = tsm_str_new(master_salt, sizeof(master_salt));
    oscf->id_context = tsm_str_new(id_context, sizeof(id_context));
    oscf->sender_id = tsm_str_new(sender_id, sizeof(sender_id));
    oscf->recipient_id = tsm_alloc(sizeof(TSM_STR) * oscf->recipient_id_count + 1);
    oscf->recipient_id[oscf->recipient_id_count++] = tsm_str_new(NULL, 0);

    osc_ctx = tsm_oscore_ctx_new(oscf);
    ASSERT(osc_ctx);

    ASSERT_0(memcmp(sender_key, osc_ctx->sender_context->sender_key->s, sizeof(sender_key)));
    ASSERT_0(
        memcmp(recipient_key, osc_ctx->recipient_chain->recipient_key->s, sizeof(recipient_key)));
    ASSERT_0(memcmp(common_iv, osc_ctx->common_iv->s, sizeof(common_iv)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, NULL, 0);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(recipient_nonce, nonce_buffer, sizeof(recipient_nonce)));

    tsm_cose_encrypt0_init(cose);
    tsm_cose_encrypt0_set_key_id(cose, osc_ctx->sender_context->sender_id->s,
                                 osc_ctx->sender_context->sender_id->length);
    tsm_cose_encrypt0_set_partial_iv(cose, NULL, 0);
    tsm_oscore_generate_nonce(cose, osc_ctx, nonce_buffer, sizeof(nonce_buffer));
    ASSERT_0(memcmp(sender_nonce, nonce_buffer, sizeof(sender_nonce)));

    tsm_oscore_ctx_free(osc_ctx);
    tsm_oscore_conf_free(oscf);

    return 0;
}

int main(void)
{
    TEST(test_oscore_1_1);
    TEST(test_oscore_1_2);
    TEST(test_oscore_2_1);
    TEST(test_oscore_2_2);
    TEST(test_oscore_3_1);
    TEST(test_oscore_3_2);

    return 0;
}
