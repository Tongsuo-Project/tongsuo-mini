/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TONGSUOMINI_INTERNAL_ASCON_H)
# define TONGSUOMINI_INTERNAL_ASCON_H
# pragma once

# include <stdint.h>
# include <tongsuo/minisuo.h>
# include <tongsuo/ascon.h>

# define ASCON_PHASE_INIT  1
# define ASCON_PHASE_AD    2
# define ASCON_PHASE_TEXT  3
# define ASCON_PHASE_FINAL 4

# pragma pack(1)
typedef struct {
    uint64_t x[5];
} ascon_state_t;

typedef struct tsm_ascon_ctx_st {
    ascon_state_t s;
    uint64_t K[2];
    uint64_t N[2];
    uint8_t mode;
    uint8_t flags;
    uint8_t block_size;
    uint8_t a;
    uint8_t b;
    uint8_t has_ad;
    uint8_t phase;
    uint8_t buf_len;
    unsigned char buf[16]; /* saved partial block */
    unsigned char tag[TSM_ASCON_AEAD_TAG_LEN];
} TSM_ASCON_CTX;

# pragma pack()

#endif
