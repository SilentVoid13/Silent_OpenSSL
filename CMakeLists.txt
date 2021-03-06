### Basic cmake setup ###

cmake_minimum_required(VERSION 3.2.1)

set(CMAKE_C_STANDARD 99)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/staticlibs)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/staticlibs)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
# For Valgrind
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

project(Silent_OpenSSL)

### Includes ###
include_directories(includes includes/tests)
include_directories(src/utilities/Silent_Log)

### Sources ###

set(SOURCES src/s_aes.c src/s_pbkdf.c src/s_base64.c src/s_aead.c src/s_curve.c src/s_digest.c)

add_library(Silent_OpenSSL STATIC ${SOURCES})

### Tests ###

set(TEST_SOURCES src/tests/test_all.c src/tests/test_aes.c src/tests/test_base64.c src/tests/test_pbkdf.c src/tests/test_aead.c src/tests/test_curve.c src/tests/test_digest.c)

add_executable(Test_Silent_OpenSSL ${TEST_SOURCES})
install(TARGETS Test_Silent_OpenSSL DESTINATION bin)

target_link_libraries(Test_Silent_OpenSSL Silent_OpenSSL)

### OpenSSL ###
find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIRS})
target_link_libraries(Test_Silent_OpenSSL ${OPENSSL_LIBRARIES})

