cmake_minimum_required(VERSION 3.5)

project(Lab2 C)
set(CMAKE_C_COMPILER=clang)
add_executable(Lab2 Lab2.c)


find_library(LIBAKRYPT_PATH NAMES libakrypt.so PATHS /usr/local/lib)
find_library(LIBAKRYPT_BASE_PATH NAMES libakrypt-base.so PATHS /usr/local/lib)

target_link_libraries(Lab2 ${LIBAKRYPT_PATH} ${LIBAKRYPT_BASE_PATH})
