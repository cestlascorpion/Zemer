cmake_minimum_required(VERSION 3.16)
project(Zemer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wconversion -Wsizeof-pointer-memaccess \
                     -Wfloat-equal -Wconversion-null -Woverflow -Wshadow -faligned-new\
                     -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -pthread -g -O0")

include_directories(src test)
link_directories(/usr/local/lib)

file(GLOB_RECURSE SRCS src/*.cpp)
file(GLOB_RECURSE HDRS src/*.h)

add_library(gmsslx STATIC ${SRCS} ${HDRS})

foreach (_target
        Encoding
        SM2
        SM3+4
        SM9)
    add_executable(${_target} "test/${_target}.cpp")
    target_link_libraries(${_target} ${PROJECT_BINARY_DIR}/libgmsslx.a gmssl)
endforeach ()