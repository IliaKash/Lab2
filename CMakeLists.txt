cmake_minimum_required(VERSION 3.5)

project(Lab2 C)
set(CMAKE_C_COMPILER=clang)
add_executable(Lab2 Lab2.c)


find_library(LIBAKRYPT_PATH NAMES libakrypt.so PATHS /home/ilia/Desktop/cryptLab2/build)
find_library(LIBAKRYPT_BASE_PATH NAMES libakrypt-base.so PATHS /home/ilia/Desktop/cryptLab2/build)

if (NOT LIBAKRYPT_PATH) 
  message(FATAL_ERROR "libakrypt not found")
endif()

if (NOT LIBAKRYPT_BASE_PATH) 
  message(FATAL_ERROR "libakrypt-base not found")
endif()
target_link_libraries(Lab2 ${LIBAKRYPT_PATH} ${LIBAKRYPT_BASE_PATH})
include_directories("/home/ilia/Desktop/cryptLab2/build" "/home/ilia/Desktop/cryptLab2/libakrypt-0.x/source")
