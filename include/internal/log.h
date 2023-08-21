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

# include <tongsuo/minisuo.h>
# include <assert.h>

# define TSM_LOG_DEBUG 0
# define TSM_LOG_ERROR 1

void tsm_log(const char *file, int line, int level, const char *fmt, ...);

# ifdef TSM_LOG
#  define LOGD(...) tsm_log(__FILE__, __LINE__, TSM_LOG_DEBUG, __VA_ARGS__)
#  define LOGE(...) tsm_log(__FILE__, __LINE__, TSM_LOG_ERROR, __VA_ARGS__)
#  define LOGERR(e) tsm_log(__FILE__, __LINE__, TSM_LOG_ERROR, "%s", tsm_err2str(e))
#  define ERRLOG(e) tsm_log(__FILE__, __LINE__, TSM_LOG_ERROR, "%s", tsm_err2str(e)), e
# else
#  define LOGD(...)
#  define LOGE(...)
#  define LOGERR(...)
#  define ERRLOG(...)
# endif

#endif
