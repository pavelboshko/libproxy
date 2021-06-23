cmake_minimum_required(VERSION 2.8)
project(libproxy_cli)
find_package(Threads)

include(FindBoost)
find_package(Boost REQUIRED COMPONENTS  program_options)

set( CMAKE_CXX_STANDARD 11 )

include_directories(
    ${CMAKE_CURRENT_LIST_DIR}/../src/
)
include(${CMAKE_CURRENT_LIST_DIR}/../build/linux/CMakeLists.txt)

#SET(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -DDEBUG")

add_executable(libproxy_cli
    ${CMAKE_CURRENT_LIST_DIR}/libproxy_cli.cpp
)
TARGET_LINK_LIBRARIES(libproxy_cli ${CMAKE_THREAD_LIBS_INIT})
TARGET_LINK_LIBRARIES(libproxy_cli ${Boost_LIBRARIES})
TARGET_LINK_LIBRARIES(libproxy_cli libproxy)
