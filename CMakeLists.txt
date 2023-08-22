CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

PROJECT(tongsuo-mini)

if (MSVC)
    # warning level 4 and all warnings as errors
    add_compile_options(/W4 /WX)
else()
    # lots of warnings and all warnings as errors
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(VERSION_MAJOR 0)
set(VERSION_MINOR 9)
set(VERSION_PATCH 0)
set(VERSION_TAG -dev)

add_definitions(-DTONGSUO_MINI_VERSION="${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}${VERSION_TAG}")

include_directories(include)

set(libsrc
    src/error.c
    src/mem.c
    src/str.c
    src/pool.c
    src/version.c
)

OPTION(WITH_ALL "Build with all modules" OFF)

OPTION(WITH_DEBUG "Enable debug" OFF)

if(WITH_DEBUG OR WITH_ALL)
    message(STATUS "DEBUG=on")
    add_definitions(-DDEBUG)
else()
    add_definitions(-DNDEBUG)
endif()

OPTION(WITH_LOG "Build with log module" OFF)

if(WITH_LOG OR WITH_ALL)
    message(STATUS "WITH_LOG=on")
    add_definitions(-DTSM_LOG)
    list(APPEND libsrc src/log.c)
endif()

OPTION(WITH_ERRSTR "Build with error string" OFF)

if(WITH_ERRSTR OR WITH_ALL)
    message(STATUS "WITH_ERRSTR=on")
    add_definitions(-DTSM_ERRSTR)
endif()

OPTION(WITH_ASN1 "Build with asn1 module" OFF)

if(WITH_ASN1 OR WITH_ALL)
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

if(WITH_SM3 OR WITH_ALL)
    message(STATUS "WITH_SM3=on")
    list(APPEND libsrc src/sm3.c)
    add_definitions(-DTSM_HAVE_SM3)

    add_executable(test_sm3 test/test_sm3.c)
    target_include_directories(test_sm3 PUBLIC test)
    target_link_libraries(test_sm3 LINK_PUBLIC tongsuo-mini)
    add_test(NAME test_sm3
        COMMAND python3 -m pytest test_sm3.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
    )
endif()

OPTION(WITH_SM4 "Build with SM4 module" OFF)

if(WITH_SM4 OR WITH_ALL)
    message(STATUS "WITH_SM4=on")
    list(APPEND libsrc src/sm4.c)
    add_definitions(-DTSM_HAVE_SM4)

    add_executable(test_sm4_api test/test_sm4_api.c)
    target_include_directories(test_sm4_api PUBLIC test)
    target_link_libraries(test_sm4_api LINK_PUBLIC tongsuo-mini)
    add_test(NAME test_sm4
        COMMAND python3 -m pytest test_sm4.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
    )
endif()

OPTION(WITH_ASCON "Build with ASCON module" OFF)

if(WITH_ASCON OR WITH_ALL)
    message(STATUS "WITH_ASCON=on")
    list(APPEND libsrc src/ascon.c)
    add_definitions(-DTSM_HAVE_ASCON)

    add_executable(test_ascon_aead test/test_ascon_aead.c)
    add_executable(test_ascon_hash test/test_ascon_hash.c)
    target_include_directories(test_ascon_aead PUBLIC test)
    target_include_directories(test_ascon_hash PUBLIC test)
    target_link_libraries(test_ascon_aead LINK_PUBLIC tongsuo-mini)
    target_link_libraries(test_ascon_hash LINK_PUBLIC tongsuo-mini)
    add_test(NAME test_ascon_aead
        COMMAND python3 -m pytest test_ascon_aead.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
    )
    add_test(NAME test_ascon_hash
        COMMAND python3 -m pytest test_ascon_hash.py
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
