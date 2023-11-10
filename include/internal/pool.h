/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_INTERNAL_POOL_H)
# define TSM_INTERNAL_POOL_H
# pragma once

# include <stddef.h>

typedef struct tsm_pool_s tsm_pool_t;

tsm_pool_t *ngx_create_pool(size_t size);
void tsm_destroy_pool(tsm_pool_t *pool);
void *tsm_palloc(tsm_pool_t *pool, size_t size);
void *tsm_pcalloc(tsm_pool_t *pool, size_t size);

#endif
