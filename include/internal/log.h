/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TONGSUOMINI_LOG_H)
# define TONGSUOMINI_LOG_H
# pragma once

# define TSM_LOG_DEBUG 0

void tsm_log(const char *func, int line, int level, const char *fmt, ...);

# ifdef TSM_DEBUG
#  define tsm_debug(...) tsm_log(__FUNCTION__, __LINE__, TSM_LOG_DEBUG, __VA_ARGS__)
# else
#  define tsm_debug(...)
# endif

#endif
