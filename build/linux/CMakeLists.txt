cmake_minimum_required(VERSION 2.8)
project(libproxy)
set(CMAKE_CXX_STANDARD 17)
find_package(Threads)
find_package(Iconv QUIET)

set( CMAKE_CXX_STANDARD 11 )

include(${CMAKE_CURRENT_LIST_DIR}/../../3rdparty/httpxx/build/linux/CMakeLists.txt)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/../../../3rdparty/boost-mobile/
    ${CMAKE_CURRENT_LIST_DIR}/../../src/
    ${CMAKE_CURRENT_LIST_DIR}/../../3rdparty/httpxx/
)

SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -std=c++17 -DDEBUG ")

ADD_LIBRARY(libproxy SHARED
    ${CMAKE_CURRENT_LIST_DIR}/../../src/libproxy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../src/callbacks_mediator.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../src/proxy_auth_basic.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../src/proxy_auth_ntlm.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../src/crypto/des.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../src/crypto/md5.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../../src/crypto/md4.cpp
)
TARGET_LINK_LIBRARIES(libproxy ${CMAKE_THREAD_LIBS_INIT} httpxx ${Iconv_LIBRARIES})
