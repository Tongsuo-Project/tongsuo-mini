/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TSM_INTERNAL_LOG_H)
# define TSM_INTERNAL_LOG_H
# pragma once

# include <tongsuo/minisuo.h>
# include <assert.h>

enum {
    TSM_LOG_DEBUG = 0,
    TSM_LOG_INFO,
    TSM_LOG_WARN,
    TSM_LOG_ERROR,
};
# ifdef TSM_LOG
void tsm_log_impl(const char *file, int line, int level, const char *fmt, ...);
# else
static inline void tsm_log_impl(const char *file, int line, int level, const char *fmt, ...)
{
    (void)file;
    (void)line;
    (void)level;
    (void)fmt;
}
# endif

# define tsm_log(level, ...) tsm_log_impl(NULL, 0, level, __VA_ARGS__)
# define LOGD(...)           tsm_log_impl(__FILE__, __LINE__, TSM_LOG_DEBUG, __VA_ARGS__)
# define LOGI(...)           tsm_log_impl(__FILE__, __LINE__, TSM_LOG_INFO, __VA_ARGS__)
# define LOGW(...)           tsm_log_impl(NULL, 0, TSM_LOG_WARN, __VA_ARGS__)
# define LOGE(...)           tsm_log_impl(NULL, 0, TSM_LOG_ERROR, __VA_ARGS__)
# define LOGERR(e)           tsm_log_impl(NULL, 0, TSM_LOG_ERROR, "%s", tsm_err2str(e))
# define eLOG(e)             tsm_log_impl(NULL, 0, TSM_LOG_ERROR, "%s", tsm_err2str(e)), e

#endif
