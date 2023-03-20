CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(tongsuo-mini)

if (MSVC)
    # warning level 4 and all warnings as errors
    add_compile_options(/W4 /WX)
else()
    # lots of warnings and all warnings as errors
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

set(VERSION_MAJOR 0)
set(VERSION_MINOR 9)
set(VERSION_PATCH 0)
set(VERSION_TAG -dev)

add_definitions(-DTONGSUO_MINI_VERSION="${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}${VERSION_TAG}")

include_directories(include)

file(GLOB_RECURSE lib_sources CONFIGURE_DEPENDS "src/*.c")
add_library(tongsuo-mini ${lib_sources})

add_executable(minisuo app/minisuo.c)
target_link_libraries(minisuo LINK_PUBLIC tongsuo-mini)

enable_testing()
add_test(NAME test
    COMMAND python3 -m pytest
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
)

OPTION(DEBUG "define TSM_DEBUG" OFF)
if (DEBUG)
    message(STATUS "TSM_DEBUG=on")
    add_definitions(-DTSM_DEBUG)
endif()
