cmake_minimum_required(VERSION 3.10)
project(dmdecrypt C)

set(CMAKE_C_STANDARD 99)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSSL REQUIRED IMPORTED_TARGET libssl)
pkg_check_modules(LIBCRYPTO REQUIRED IMPORTED_TARGET libcrypto)

add_executable(dmdecrypt main.c)
target_link_libraries(dmdecrypt PkgConfig::LIBSSL PkgConfig::LIBCRYPTO m)
