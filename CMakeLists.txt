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

set(libsrc
    src/error.c
    src/mem.c
    src/pool.c
    src/version.c
)

OPTION(WITH_DEBUG "Enable debug" OFF)
if (DEBUG)
    message(STATUS "DEBUG=on")
    add_definitions(-DDEBUG)
else()
    add_definitions(-DNDEBUG)
endif()

OPTION(WITH_LOG "Build with log module" OFF)
if(WITH_LOG)
    message(STATUS "WITH_LOG=on")
    add_definitions(-DTSM_LOG)
    list(APPEND libsrc src/log.c)
endif()

OPTION(WITH_ASN1 "Build with asn1 module" OFF)
if (WITH_ASN1)
    message(STATUS "WITH_ASN1=on")
    list(APPEND libsrc src/asn1.c)

    add_executable(test_asn1 test/test_asn1.c)
    target_include_directories(test_asn1 PUBLIC test)
    target_link_libraries(test_asn1 LINK_PUBLIC tongsuo-mini)
    add_test(NAME test_asn1
        COMMAND python3 -m pytest test_asn1.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
    )
endif()

OPTION(WITH_SM3 "Build with SM3 module" OFF)
if (WITH_SM3)
    message(STATUS "WITH_SM3=on")
    list(APPEND libsrc src/sm3.c)

    add_executable(test_sm3 test/test_sm3.c)
    target_include_directories(test_sm3 PUBLIC test)
    target_link_libraries(test_sm3 LINK_PUBLIC tongsuo-mini)
    add_test(NAME test_sm3
        COMMAND python3 -m pytest test_sm3.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
    )
endif()

add_library(tongsuo-mini ${libsrc})

add_executable(minisuo app/minisuo.c)
target_link_libraries(minisuo LINK_PUBLIC tongsuo-mini)

enable_testing()
add_test(NAME test_minisuo
    COMMAND python3 -m pytest test_minisuo.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
)
