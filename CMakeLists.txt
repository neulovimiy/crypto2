cmake_minimum_required(VERSION 3.5.0)
project(EntropyRSA VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)

add_executable(EntropyRSA main.cpp rsa_generator.cpp aes_generator.cpp resource.rc "C:/Program Files/OpenSSL-Win64/include/openssl/applink.c" ecc_ecdsa.cpp
)

set(OPENSSL_INCLUDE_DIR "C:/Program Files/OpenSSL-Win64/include")
set(OPENSSL_LIBRARIES "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libssl.lib" "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libcrypto.lib")

target_include_directories(EntropyRSA PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(EntropyRSA ${OPENSSL_LIBRARIES})

target_link_libraries(EntropyRSA user32 gdi32 comctl32 advapi32 crypt32)