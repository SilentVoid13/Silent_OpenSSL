//
// Created by silentvoid on 4/14/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#include "s_pbkdf.h"
#include "s_openssl.h"

/**
 * PBKDF2 key derivation
 *
 * @return plaintext length on success, -1 on failure
 */
int s_pbkdf2_hmac_derive(const char *password, size_t password_len, const unsigned char *salt, size_t salt_len, size_t iterations, char *digest_mode, unsigned char *output_key, size_t output_key_len) {
    const EVP_MD *evp_digest;
    if(strcmp(digest_mode, "sha1") == 0) {
        evp_digest = EVP_sha1();
    }
    else if(strcmp(digest_mode, "sha256") == 0) {
        evp_digest = EVP_sha256();
    }
    else if(strcmp(digest_mode, "sha512") == 0) {
        evp_digest = EVP_sha512();
    }
    else {
        fprintf(stderr, "Unknown digest mode\n");
        return -1;
    }

    if(PKCS5_PBKDF2_HMAC(password, password_len, salt, salt_len, iterations, evp_digest, output_key_len, output_key) == 0) {
        fprintf(stderr, "PKCS5_PBKDF2_HMAC() failure\n");
        return -1;
    }

    return 1;
}
