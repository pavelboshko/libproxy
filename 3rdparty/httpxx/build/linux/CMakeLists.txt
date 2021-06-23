cmake_minimum_required(VERSION 2.8)
project(httpxx)

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/../../httpxx/
    ${CMAKE_CURRENT_LIST_DIR}/../../httpxx/http-parser/
    ${CMAKE_CURRENT_LIST_DIR}/../../
)

#ADD_DEFINITIONS(-DSCCRYPT=${SCCRYPT})
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -std=c++11 -g -ggdb -gstabs -DLOG_TO_STD -DLOG_TO_NATIVE -DLOG_TO_FILE")

file(GLOB SOURCES ${CMAKE_CURRENT_LIST_DIR}/../../httpxx/*.cpp)
add_library(httpxx SHARED
    ${CMAKE_CURRENT_LIST_DIR}/../../httpxx/http-parser/http_parser.c
    ${SOURCES}   
)
