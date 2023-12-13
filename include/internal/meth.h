/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_INTERNAL_METH_H)
# define TSM_INTERNAL_METH_H
# pragma once

# include <stdlib.h>

typedef struct {
    const char *name;
    uint8_t alg;
    uint8_t hashsize;
    uint8_t blocksize;
    void *(*newctx)(void);
    void (*freectx)(void *ctx);
    int (*init)(void *ctx);
    int (*update)(void *ctx, const unsigned char *data, size_t len);
    int (*final)(void *ctx, unsigned char *out, size_t *outl);
} TSM_HASH_METH;

void *tsm_get_hash_meth(int alg);
#endif
