/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <internal/log.h>
#include <internal/mem.h>
#include <stdlib.h>
#include <string.h>

void *tsm_alloc(size_t size)
{
    void *ptr = malloc(size);
    tsm_debug("malloc %p:%z", ptr, size);
    return ptr;
}

void *tsm_calloc(size_t size)
{
    void *ptr;

    ptr = tsm_alloc(size);
    if (ptr)
        tsm_memzero(ptr, size);

    return ptr;
}

void tsm_free(void *ptr)
{
    free(ptr);
    tsm_debug("free %p", ptr);
}

inline void tsm_memzero(void *ptr, size_t size)
{
    (void)memset(ptr, 0, size);
}
