cmake_minimum_required(VERSION 3.10)
project(litterTCB)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0")

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/include
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

file(GLOB ETH_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/eth/*.c")
file(GLOB LIB_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
file(GLOB LIB_SRC_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/lib/src/*.c")

add_executable(litterTCP  
    ${ETH_SOURCES} 
    ${LIB_SOURCES}
    ${LIB_SRC_SOURCES}
)

target_link_libraries(litterTCP pthread)

add_custom_target(cleanup
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_BINARY_DIR}/CMakeFiles
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/CMakeCache.txt
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/litterTCB
    COMMENT "Cleaning up build files"
)
