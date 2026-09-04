# Ze'mer

Ze'mer is a C++17 wrapper around [GmSSL v3.1.1](https://github.com/guanzhi/GmSSL.git). It provides convenient APIs for SM2, SM3, SM4, SM9, and Base16, Base32, and Base64 encoding.

## Prerequisites

- A C++17 compiler
- CMake 3.16 or later
- GmSSL v3.1.1 headers and library installed locally

The default CMake configuration links GmSSL from `/usr/local/lib`. Ensure the GmSSL headers are available in the compiler include path.

## Build

```sh
cmake -S . -B build
cmake --build build -j
```

## Test

```sh
ctest --test-dir build --output-on-failure
```

The test executables cover encoding and the supported SM2, SM3, SM4, and SM9 operations.
