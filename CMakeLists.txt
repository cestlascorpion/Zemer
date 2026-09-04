cmake_minimum_required(VERSION 3.16)

project(Zemer LANGUAGES CXX)

find_package(Threads REQUIRED)
find_path(GMSSL_INCLUDE_DIR gmssl/sm2.h PATHS /usr/local/include)
find_library(GMSSL_LIBRARY NAMES gmssl PATHS /usr/local/lib)

if(NOT GMSSL_INCLUDE_DIR OR NOT GMSSL_LIBRARY)
    message(FATAL_ERROR "GmSSL headers and library are required")
endif()

set(PROJECT_WARNINGS
    -Wall
    -Wextra
    -Wconversion
    -Wsizeof-pointer-memaccess
    -Wfloat-equal
    -Wconversion-null
    -Woverflow
    -Wshadow
    -faligned-new)

file(GLOB_RECURSE ZEMER_SOURCES CONFIGURE_DEPENDS src/*.cpp)
file(GLOB_RECURSE ZEMER_HEADERS CONFIGURE_DEPENDS src/*.h)

add_library(gmsslx STATIC ${ZEMER_SOURCES} ${ZEMER_HEADERS})
set_target_properties(gmsslx PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES CXX_EXTENSIONS NO)
target_compile_definitions(gmsslx PRIVATE _FILE_OFFSET_BITS=64 _GNU_SOURCE)
target_compile_features(gmsslx PUBLIC cxx_std_17)
target_compile_options(gmsslx PRIVATE ${PROJECT_WARNINGS} -g -O0)
target_include_directories(gmsslx PUBLIC src PRIVATE ${GMSSL_INCLUDE_DIR})
target_link_libraries(gmsslx PUBLIC Threads::Threads)

include(CTest)
if(BUILD_TESTING)
    foreach(target Encoding SM2 SM3+4 SM9)
        add_executable(${target} test/${target}.cpp)
        target_compile_options(${target} PRIVATE ${PROJECT_WARNINGS} -g -O0)
        target_include_directories(${target} PRIVATE test)
        target_link_libraries(${target} PRIVATE gmsslx ${GMSSL_LIBRARY})
        add_test(NAME ${target} COMMAND ${target})
    endforeach()
endif()
