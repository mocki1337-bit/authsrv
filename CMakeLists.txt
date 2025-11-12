cmake_minimum_required(VERSION 3.15)
project(authsrv LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE STRING "")
endif()


include_directories(${CMAKE_SOURCE_DIR}/third_party/include)


find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)


add_executable(authsrv main.cpp)


target_link_libraries(authsrv PRIVATE SQLite::SQLite3 OpenSSL::Crypto OpenSSL::SSL CURL::libcurl)
