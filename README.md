# Zemer

Zemer is a C++17 wrapper for GmSSL v3.1.1 that exposes SM2, SM3, SM4, SM9, and Base16, Base32, and Base64 helpers.

## Requirements

- CMake 3.16 or later
- A C++17 compiler
- GmSSL headers and library

## Build

```sh
cmake -S . -B build
cmake --build build
```

## Test

```sh
ctest --test-dir build --output-on-failure
```
