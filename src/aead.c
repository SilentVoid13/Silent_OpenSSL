//
// Created by silentvoid on 4/14/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#include "aead.h"
#include "openssl.h"

#include "log.h"

/**
 * AEAD encryption
 *
 * @return ciphertext_len on success, -1 on failure
 */
int aead_aes_256_gcm_encrypt(unsigned char *plaintext, size_t plaintext_len, unsigned char *aad, size_t aad_len, unsigned char *key, unsigned char *iv, size_t iv_len, unsigned char **ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;

    size_t ciphertext_len = (plaintext_len / BLOCKSIZE + 1) * BLOCKSIZE;
    // Cipher length always greater or equal to plaintext
    *ciphertext = malloc(ciphertext_len);
    if(*plaintext == 0) {
        free(*ciphertext);
        log_error("malloc() failure");
        return -1;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        free(*ciphertext);
        log_error("EVP_CIPHER_CTX_new() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        free(*ciphertext);
        log_error("EVP_EncryptInit_ex() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Not useful if iv_len = 12
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        free(*ciphertext);
        log_error("EVP_CIPHER_CTX_ctrl() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        free(*ciphertext);
        log_error("EVP_EncryptInit_ex() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(aad != NULL) {
        // Provide any AAD data
        if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
            free(*ciphertext);
            log_error("EVP_EncryptUpdate() failure");
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }

    if(!EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len)) {
        free(*ciphertext);
        log_error("EVP_EncryptUpdate() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ciphertext_len = len;

    if(1 > EVP_EncryptFinal_ex(ctx, (*ciphertext)+len, &len)) {
        free(*ciphertext);
        log_error("EVP_EncryptFinal_ex() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) {
        free(*ciphertext);
        log_error("EVP_CIPHER_CTX_ctrl() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    ciphertext_len += len;
    (*ciphertext)[ciphertext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/**
 * AEAD decryption
 *
 * @return plaintext_len on success, -1 on failure
 */
int aead_aes_256_gcm_decrypt(unsigned char *ciphertext, size_t ciphertext_len, unsigned char *aad, size_t aad_len, unsigned char *key, unsigned char *iv, size_t iv_len, unsigned char **plaintext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Cipher length always greater or equal to plaintext
    *plaintext = malloc(ciphertext_len);
    if(*plaintext == 0) {
        free(*plaintext);
        log_error("malloc() failure");
        return -1;
    }

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        free(*plaintext);
        log_error("EVP_CIPHER_CTX_new() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        free(*plaintext);
        log_error("EVP_DecryptInit_ex() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Not useful if iv_len = 12
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        free(*plaintext);
        log_error("EVP_CIPHER_CTX_ctrl() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        free(*plaintext);
        log_error("EVP_DecryptInit_ex() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(aad != NULL) {
        // Provide any AAD data
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
            free(*plaintext);
            log_error("EVP_DecryptUpdate() failure");
            ERR_print_errors_fp(stderr);
            return -1;
        }
    }

    if(!EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len)) {
        free(*plaintext);
        log_error("EVP_DecryptUpdate() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len = len;

    // Set the expected tag value for authenticated data
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        free(*plaintext);
        log_error("EVP_CIPHER_CTX_ctrl() failure");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // If auth failed or anything else
    if(1 > EVP_DecryptFinal_ex(ctx, (*plaintext)+len, &len)) {
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
