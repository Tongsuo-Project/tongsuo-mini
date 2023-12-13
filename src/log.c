/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "internal/log.h"

#define TSM_MAX_LOG_STRLEN 2048

static int default_log_level = TSM_LOG_ERROR;

const char *log_level[] = {
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
};

void tsm_log_impl(const char *file, int line, int level, const char *fmt, ...)
{
    char *p, *end;
    va_list args;
    char msg[TSM_MAX_LOG_STRLEN];

    if (level < default_log_level)
        return;

    p = msg;
    end = p + sizeof(msg) - 1;

    if (file != NULL) {
        p += snprintf(p, end - p, "[%s]|[%s:%d]|", log_level[level], file, line);
        if (p > end)
            return;
    }

    va_start(args, fmt);
    p += vsnprintf(p, end - p, fmt, args);
    va_end(args);

    if (p > end) {
        memcpy(end - 5, "[...]", 5);
        p = end;
    }

    *p++ = '\n';

    fprintf(stderr, "%.*s", (int)(p - msg), msg);
}
