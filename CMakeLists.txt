cmake_minimum_required(VERSION 3.10)
project(authsrv VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_definitions(-Wall -Wextra -Wpedantic)

# Найдём зависимости
find_package(CURL REQUIRED)        # предоставляет CURL::libcurl (в новых CMake)
find_package(OpenSSL REQUIRED)     # OpenSSL::SSL OpenSSL::Crypto
find_package(SQLite3 REQUIRED)     # устанавливает SQLITE3_LIBRARIES / SQLITE3_INCLUDE_DIR
find_package(nlohmann_json QUIET)  # если установлен в системе - подключим

# Исполняемый файл
add_executable(authsrv main.cpp)

# Убедимся, что директория с заголовками проекта (root или include) видна
target_include_directories(authsrv PRIVATE
  ${CMAKE_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${SQLite3_INCLUDE_DIRS}   # если установлен
)

# Формируем корректный список библиотек для линковки (фолбекы)
set(_LIBS "")
if(TARGET CURL::libcurl)
  list(APPEND _LIBS CURL::libcurl)
elseif(DEFINED CURL_LIBRARIES)
  list(APPEND _LIBS ${CURL_LIBRARIES})
endif()

if(TARGET OpenSSL::SSL)
  list(APPEND _LIBS OpenSSL::SSL OpenSSL::Crypto)
elseif(DEFINED OPENSSL_LIBRARIES)
  list(APPEND _LIBS ${OPENSSL_LIBRARIES})
endif()

if(DEFINED SQLITE3_LIBRARIES)
  list(APPEND _LIBS ${SQLITE3_LIBRARIES})
elseif(DEFINED SQLITE3_LIBRARY)
  list(APPEND _LIBS ${SQLITE3_LIBRARY})
else()
  list(APPEND _LIBS sqlite3) # последний фолбек
endif()

# Если nlohmann_json найден как target — подключим
if (TARGET nlohmann_json::nlohmann_json)
  list(APPEND _LIBS nlohmann_json::nlohmann_json)
endif()

target_link_libraries(authsrv PRIVATE ${_LIBS})

# Доп: полезная опция сборки
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

