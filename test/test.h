/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/tongsuo-mini/blob/main/LICENSE
 */

#if !defined(TONGSUOMINI_TEST_H)
# define TONGSUOMINI_TEST_H
# pragma once

# include "internal/asn1.h"
# include <stdio.h>
# include <stdlib.h>
# include <tongsuo/minisuo.h>

# define TEST(func) RUN_TEST(__FILE__, __LINE__, func)
# define RUN_TEST(file, line, func)                                                                \
     do {                                                                                          \
         int ret = func();                                                                         \
         if (ret) {                                                                                \
             fprintf(stderr, "Failed\t%s\t%s:%d\n", #func, file, line);                            \
             return ret;                                                                           \
         } else {                                                                                  \
             fprintf(stderr, "Passed\t%s\t%s:%d\n", #func, file, line);                            \
         }                                                                                         \
     } while (0)
# define TEST_EX(func, ...) RUN_TEST_WITH_ARGS(__FILE__, __LINE__, func, __VA_ARGS__)
# define RUN_TEST_WITH_ARGS(file, line, func, ...)                                                 \
     do {                                                                                          \
         int ret = func(__VA_ARGS__);                                                              \
         if (ret) {                                                                                \
             fprintf(stderr, "Failed\t%s\t%s:%d\n", #func, file, line);                            \
             return ret;                                                                           \
         } else {                                                                                  \
             fprintf(stderr, "Passed\t%s\t%s:%d\n", #func, file, line);                            \
         }                                                                                         \
     } while (0)

# define TESTS(...) RUN_TESTS(__VA_ARGS__, __FILE__, __LINE__)
# define RUN_TESTS(func, n, file, line)                                                            \
  for (int i = 0; i < n; i++) {                                                                    \
   int ret = func(i);                                                                              \
   if (ret) {                                                                                      \
    fprintf(stderr, "Failed\t%s(%d)\t%s:%d\n", #func, i, file, line);                              \
    return ret;                                                                                    \
   } else {                                                                                        \
    fprintf(stderr, "Passed\t%s(%d)\t%s:%d\n", #func, i, file, line);                              \
   }                                                                                               \
  }

# define ASSERT(exp)     TEST_ASSERT((exp), __FILE__, __LINE__)
# define ASSERT_0(ret)   TEST_ASSERT(((ret) == 0), __FILE__, __LINE__)
# define ASSERT_OK(ret)  TEST_ASSERT(((ret) == TSM_OK), __FILE__, __LINE__)
# define ASSERT_ERR(ret) TEST_ASSERT(((ret) != TSM_OK), __FILE__, __LINE__)

# define TEST_ASSERT(exp, func, line)                                                              \
     do {                                                                                          \
         if (exp) {                                                                                \
             ;                                                                                     \
         } else {                                                                                  \
             TEST_FAIL((func), (line));                                                            \
         }                                                                                         \
     } while (0)

static inline void TEST_FAIL(const char *func, int line)
{
    fprintf(stderr, "Assert Failed\t%s:%d\n", func, line);
    exit(1);
}

#endif
