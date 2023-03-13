CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(tongsuo-mini)

set(VERSION_MAJOR 0)
set(VERSION_MINOR 9)
set(VERSION_PATCH 0)
set(VERSION_TAG -dev)

add_definitions(-DTONGSUO_MINI_VERSION="${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}${VERSION_TAG}")

include_directories(include)

set(LIB_SRC
    src/version.c
)

add_library(tongsuo-mini ${LIB_SRC})

add_executable(minisuo app/minisuo.c)
target_link_libraries(minisuo LINK_PUBLIC tongsuo-mini)

enable_testing()
add_test(NAME test
    COMMAND python3 -m pytest
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
)
