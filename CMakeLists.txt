cmake_minimum_required(VERSION 3.10)
project(authsrv)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(authsrv main.cpp)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

target_include_directories(authsrv PRIVATE
    ${CMAKE_SOURCE_DIR}       # чтобы видеть httplib.h in root
)

target_link_libraries(authsrv PRIVATE
    ${CURL_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    ${SQLITE3_LIBRARIES}
)
