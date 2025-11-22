cmake_minimum_required(VERSION 3.10)
project(authsrv)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Добавляем исходники
set(SOURCES
    main.cpp
    # добавь сюда другие .cpp файлы, если они есть
)

# Создаем исполняемый файл
add_executable(authsrv ${SOURCES})

# Подключаем библиотеки
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

target_include_directories(authsrv PRIVATE ${CURL_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(authsrv PRIVATE ${CURL_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto ${SQLITE3_LIBRARIES})
