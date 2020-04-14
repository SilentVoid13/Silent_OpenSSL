//
// Created by silentvoid on 4/14/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#include "aes.h"
#include "openssl.h"

#include "log.h"

/**
 * AES encryption
 *
 * @return ciphertext length on success, -1 on failure
 */
int aes_encrypt(char *aes_mode, unsigned char *plaintext, size_t plaintext_len, unsigned char *key, unsigned char *iv, unsigned char **ciphertext) {
    const EVP_CIPHER *evp_aes;
    if (strcmp(aes_mode, "aes_128_ecb") == 0) {
        evp_aes = EVP_aes_128_ecb();
    } else if (strcmp(aes_mode, "aes_128_cbc") == 0) {
        evp_aes = EVP_aes_128_cbc();
    } else if (strcmp(aes_mode, "aes_128_ctr") == 0) {
        evp_aes = EVP_aes_128_ctr();
    } else if (strcmp(aes_mode, "aes_256_ecb") == 0) {
        evp_aes = EVP_aes_256_ecb();
    } else if (strcmp(aes_mode, "aes_256_cbc") == 0) {
        evp_aes = EVP_aes_256_cbc();
    } else if (strcmp(aes_mode, "aes_256_ctr") == 0) {
        evp_aes = EVP_aes_256_ctr();
    } else {
        log_error("Unknown AES mode");
        return -1;
    }

    EVP_CIPHER_CTX *ctx = NULL;
    int len;

    size_t ciphertext_len = (plaintext_len / BLOCKSIZE + 1) * BLOCKSIZE;
    *ciphertext= malloc(ciphertext_len + 1);
    if(*ciphertext == NULL) {
        free(*ciphertext);
        log_error("malloc() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    (*ciphertext)[ciphertext_len] = '\0';

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        free(*ciphertext);
        log_error("EVP_CIPHER_CTX_new() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, evp_aes, NULL, key, iv)) {
        free(*ciphertext);
        log_error("EVP_EncryptInit_ex() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Disabling padding is actually useless we already have a valid ciphertext length
    //EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) {
        free(*ciphertext);
        log_error("EVP_EncryptUpdate() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, (*ciphertext) + len, &len)) {
        free(*ciphertext);
        log_error("EVP_EncryptFinal_ex() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ciphertext_len += len;
    (*ciphertext)[ciphertext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/**
 * AES decryption
 *
 * @return plaintext length on success, -1 on failure
 */
int aes_decrypt(char *aes_mode, unsigned char *ciphertext, size_t ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char **plaintext) {
    const EVP_CIPHER *evp_aes;
    if(strcmp(aes_mode, "aes_128_ecb") == 0) {
        evp_aes = EVP_aes_128_ecb();
    }
    else if(strcmp(aes_mode, "aes_128_cbc") == 0) {
        evp_aes = EVP_aes_128_cbc();
    }
    else if(strcmp(aes_mode, "aes_128_ctr") == 0) {
        evp_aes = EVP_aes_128_ctr();
    }
    else if(strcmp(aes_mode, "aes_256_ecb") == 0) {
        evp_aes = EVP_aes_256_ecb();
    }
    else if(strcmp(aes_mode, "aes_256_cbc") == 0) {
        evp_aes = EVP_aes_256_cbc();
    }
    else if(strcmp(aes_mode, "aes_256_ctr") == 0) {
        evp_aes = EVP_aes_256_ctr();
    }
    else {
        log_error("Unknown AES mode");
        return -1;
    }

    // TODO: Check ciphertext_len (multiple of 128 or 256)

    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int plaintext_len;

    // The ciphertext is always greater or equal to the length of the plaintext
    *plaintext = malloc(ciphertext_len + 1);
    if(*plaintext == NULL) {
        free(*plaintext);
        log_error("malloc() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    (*plaintext)[ciphertext_len] = '\0';

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        free(*plaintext);
        log_error("EVP_CIPHER_CTX_new() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(1 != EVP_DecryptInit_ex(ctx, evp_aes, NULL, key, iv)) {
        free(*plaintext);
        log_error("EVP_DecryptInit_ex() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Disabling padding is actually useless we already have a valid ciphertext length
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if(1 != EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) {
        free(*plaintext);
        log_error("EVP_DecryptUpdate() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, (*plaintext)+len, &len)) {
        free(*plaintext);
        log_error("EVP_DecryptFinal_ex() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len += len;
    (*plaintext)[plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
