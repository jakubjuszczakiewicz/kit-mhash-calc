# Copyright (c) 2025 Krypto-IT Jakub Juszczakiewicz
# All rights reserved.

cmake_minimum_required(VERSION 3.5)
project(kit-mhash-calc C)

find_package(OpenSSL)
find_package(Threads)

set(SOURCE_FILES
  src/main.c
  src/version.c
)

set(BUFFER_SIZE "10485760" CACHE STRING "Internal buffer size")
if (BUFFER_SIZE)
  add_definitions("-DBUFFER_SIZE=${BUFFER_SIZE}")
endif()

add_executable(${PROJECT_NAME} ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} ssl OpenSSL::Crypto Threads::Threads)
