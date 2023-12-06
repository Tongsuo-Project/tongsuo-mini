CMAKE_MINIMUM_REQUIRED(VERSION 2.8.8)

PROJECT(tongsuo-mini)

if (MSVC)
    # warning level 4 and all warnings as errors
    add_compile_options(/W4 /WX)
else()
    # lots of warnings and all warnings as errors
    add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(MSVC)
    set(TONGSUO_MINI_INSTALL_DIR C:/tongsuo-mini)
else()
    set(TONGSUO_MINI_INSTALL_DIR /opt/tongsuo-mini)
endif()

include_directories(include)

set(libsrc
    src/error.c
    src/mem.c
    src/pool.c
    src/version.c
)

# All options, in alphabetic order
OPTION(WITH_ALL "Build with all modules" OFF)
OPTION(WITH_ASCON "Build with ASCON module" OFF)
OPTION(WITH_ASN1 "Build with asn1 module" OFF)
OPTION(WITH_DEBUG "Enable debug" OFF)
OPTION(WITH_ERRSTR "Build with error string" OFF)
OPTION(WITH_HMAC "Build with HMAC module" OFF)
OPTION(WITH_LOG "Build with log module" OFF)
OPTION(WITH_OSCORE "Build with OSCORE module" OFF)
OPTION(WITH_PERF "Build performance test program" OFF)
OPTION(WITH_SM3 "Build with SM3 module" OFF)
OPTION(WITH_SM4 "Build with SM4 module" OFF)

if(WITH_ALL)
    set(WITH_ASCON ON)
    set(WITH_ASN1 ON)
    set(WITH_DEBUG ON)
    set(WITH_ERRSTR ON)
    set(WITH_HMAC ON)
    set(WITH_LOG ON)
    set(WITH_OSCORE ON)
    set(WITH_PERF ON)
    set(WITH_SM3 ON)
    set(WITH_SM4 ON)
endif()

if(WITH_DEBUG)
    add_definitions(-DDEBUG)
    set(CMAKE_BUILD_TYPE "Debug")
else()
    add_definitions(-DNDEBUG)
    set(CMAKE_BUILD_TYPE "Release")
endif()

if(WITH_LOG)
    add_definitions(-DTSM_LOG)
    list(APPEND libsrc src/log.c)
endif()

if(WITH_ERRSTR)
    add_definitions(-DTSM_ERRSTR)
endif()

if(WITH_ASN1)
    list(APPEND libsrc src/asn1.c)

    add_executable(test_asn1 test/test_asn1.c)
    target_include_directories(test_asn1 PUBLIC test)
    target_link_libraries(test_asn1 LINK_PUBLIC tongsuo-mini)
    add_test(NAME test_asn1
        COMMAND python3 -m pytest test_asn1.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
    )
endif()

if(WITH_SM3 OR WITH_PERF)
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

if(WITH_SM4 OR WITH_PERF)
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

if(WITH_OSCORE)
    set(WITH_ASCON ON)
    set(WITH_HMAC ON)

    list(APPEND libsrc src/oscore_cbor.c src/oscore_context.c src/oscore_cose.c src/oscore_crypto.c src/oscore.c)
    add_executable(test_oscore test/test_oscore.c)
    target_include_directories(test_oscore PUBLIC test)
    target_link_libraries(test_oscore LINK_PUBLIC tongsuo-mini)
    add_test(NAME test_oscore
        COMMAND python3 -m pytest test_oscore.py
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
    )
endif()

if(WITH_ASCON OR WITH_PERF)
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

if(WITH_HMAC)
    list(APPEND libsrc src/hmac.c)

    if(WITH_ASCON)
        add_executable(test_ascon_hmac test/test_ascon_hmac.c)
        target_include_directories(test_ascon_hmac PUBLIC test)
        target_link_libraries(test_ascon_hmac LINK_PUBLIC tongsuo-mini)
        add_test(NAME test_ascon_hmac
            COMMAND python3 -m pytest test_ascon_hmac.py
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
        )
    endif()
endif()

add_library(tongsuo-mini-obj OBJECT ${libsrc})
set_property(TARGET tongsuo-mini-obj PROPERTY POSITION_INDEPENDENT_CODE 1)
add_library(tongsuo-mini SHARED STATIC ${libsrc})

add_executable(minisuo app/minisuo.c)
target_link_libraries(minisuo LINK_PUBLIC tongsuo-mini)

if(WITH_PERF)
    add_executable(minisuo-perf perf/perf.c)
    target_link_libraries(minisuo-perf LINK_PUBLIC tongsuo-mini)
endif()

enable_testing()
add_test(NAME test_minisuo
    COMMAND python3 -m pytest test_minisuo.py
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/test
)

# show options
message(STATUS "")
message(STATUS "Tongsuo Mini Configuration Summary:")
message(STATUS "")
message(STATUS "WITH_ALL...................${WITH_ALL}")
message(STATUS "WITH_ASCON.................${WITH_ASCON}")
message(STATUS "WITH_ASN1..................${WITH_ASN1}")
message(STATUS "WITH_DEBUG.................${WITH_DEBUG}")
message(STATUS "WITH_ERRSTR................${WITH_ERRSTR}")
message(STATUS "WITH_HMAC..................${WITH_HMAC}")
message(STATUS "WITH_LOG...................${WITH_LOG}")
message(STATUS "WITH_OSCORE................${WITH_OSCORE}")
message(STATUS "WITH_PERF..................${WITH_PERF}")
message(STATUS "WITH_SM3...................${WITH_SM3}")
message(STATUS "WITH_SM4...................${WITH_SM4}")

#
# install
#
install(DIRECTORY ${CMAKE_CURRENT_LIST_DIR}/include/tongsuo
    DESTINATION ${TONGSUO_MINI_INSTALL_DIR}/include/
    COMPONENT dev)

install(TARGETS tongsuo-mini
    LIBRARY DESTINATION ${TONGSUO_MINI_INSTALL_DIR}/lib COMPONENT lib
    ARCHIVE DESTINATION ${TONGSUO_MINI_INSTALL_DIR}/lib COMPONENT lib)

install(TARGETS minisuo
    DESTINATION ${TONGSUO_MINI_INSTALL_DIR}/bin
    COMPONENT dev)

if(WITH_PERF OR WITH_ALL)
    install(TARGETS minisuo-perf
        DESTINATION ${TONGSUO_MINI_INSTALL_DIR}/bin
        COMPONENT dev)
endif()
