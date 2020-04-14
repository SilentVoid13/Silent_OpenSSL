### Basic cmake setup ###

cmake_minimum_required(VERSION 3.2.1)

set(CMAKE_C_STANDARD 99)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/staticlibs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/staticlibs)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")

project(Silent_OpenSSL)

### Includes ###
include_directories(includes includes/tests)
include_directories(src/utilities/Silent_Log)

### Sources ###

set(SOURCES src/aes.c src/pbkdf.c src/base64.c src/aead.c)

add_library(Silent_OpenSSL STATIC ${SOURCES})

### Tests ###

set(TEST_SOURCES src/tests/test_all.c src/tests/test_aes.c src/tests/test_base64.c src/tests/test_pbkdf.c src/tests/test_aead.c)

add_executable(Test_Silent_OpenSSL ${TEST_SOURCES})
install(TARGETS Test_Silent_OpenSSL DESTINATION bin)

target_link_libraries(Test_Silent_OpenSSL Silent_OpenSSL)

### OpenSSL ###
find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIRS})
target_link_libraries(Test_Silent_OpenSSL ${OPENSSL_LIBRARIES})

