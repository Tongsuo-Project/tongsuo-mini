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

# include <tongsuo/error.h>
# include <assert.h>

# define TSM_LOG_DEBUG 0
# define TSM_LOG_ERROR 1

void tsm_log(const char *file, int line, int level, const char *fmt, ...);

# ifdef TSM_LOG
#  define LOGD(...) tsm_log(__FILE__, __LINE__, TSM_LOG_DEBUG, __VA_ARGS__)
#  define LOGE(...) tsm_log(__FILE__, __LINE__, TSM_LOG_ERROR, __VA_ARGS__)
# else
#  define LOGD(...)
#  define LOGE(...)
# endif

# define CHECKP(x)                                                                                 \
  do {                                                                                             \
   if (!(x)) {                                                                                     \
    LOGE("Check '%s' failed on %s:%d", #x, __FILE__, __LINE__);                                    \
    assert(0);                                                                                     \
    return ERR_PASS_NULL_PARAM;                                                                    \
   }                                                                                               \
  } while (0);

#endif
