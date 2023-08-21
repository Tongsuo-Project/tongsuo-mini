/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TONGSUOMINI_MEM_H)
# define TONGSUOMINI_MEM_H
# pragma once

# include <stddef.h>

void *tsm_alloc(size_t size);
void *tsm_calloc(size_t size);
void tsm_free(void *ptr);
void tsm_memzero(void *ptr, size_t size);

int tsm_hex2bin(const char *str, unsigned char *buf, long *buflen);
unsigned char *tsm_hex2buf(const char *str);

#endif
