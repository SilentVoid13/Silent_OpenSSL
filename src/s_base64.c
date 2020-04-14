//
// Created by silentvoid on 4/14/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#include "s_base64.h"
#include "s_openssl.h"

/**
 * Get the base64 plaintext len with a base64 string
 *
 * @return plaintext size
 */
size_t calc_base64_length(const unsigned char *b64input) {
    size_t len = strlen((char *)b64input);
    size_t padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=')
        padding = 2;
    else if (b64input[len-1] == '=')
        padding = 1;

    return (len*3)/4 - padding;
}

int base64_encode(const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext) {
    // Max size with padding of 2
    size_t ciphertext_len = 4 * ((plaintext_len+2)/3);
    int len;

    *ciphertext = malloc(ciphertext_len + 1);
    if(*ciphertext == NULL) {
        free(*ciphertext);
        fprintf(stderr, "malloc() failure\n");
        return -1;
    }
    (*ciphertext)[ciphertext_len] = '\0';

    EVP_ENCODE_CTX *ctx;
    if(!(ctx = EVP_ENCODE_CTX_new())) {
        free(*ciphertext);
        fprintf(stderr, "EVP_ENCODE_CTX_new() failure\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_EncodeInit(ctx);

    if(1 != (EVP_EncodeUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len))) {
        free(*ciphertext);
        fprintf(stderr, "EVP_EncodeUpdate() failure\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ciphertext_len = len;

    EVP_EncodeFinal(ctx, (*ciphertext) + len, &len);

    ciphertext_len += len;
    (*ciphertext)[ciphertext_len] = '\0';
    EVP_ENCODE_CTX_free(ctx);

    return ciphertext_len;
}

int base64_decode(const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **plaintext) {
    size_t plaintext_len = calc_base64_length(ciphertext);
    int len;

    *plaintext = malloc(plaintext_len + 1);
    if(*plaintext == NULL) {
        free(*plaintext);
        fprintf(stderr, "malloc() failure\n");
        return -1;
    }
    (*plaintext)[plaintext_len] = '\0';

    EVP_ENCODE_CTX *ctx;
    if(!(ctx = EVP_ENCODE_CTX_new())) {
        free(*plaintext);
        fprintf(stderr, "EVP_ENCODE_CTX_new() failure\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_DecodeInit(ctx);

    if(EVP_DecodeUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len) == -1) {
        free(*plaintext);
        fprintf(stderr, "EVP_DecodeUpdate() failure\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len = len;

    EVP_DecodeFinal(ctx, (*plaintext) + len, &len);

    plaintext_len += len;
    (*plaintext)[plaintext_len] = '\0';
    EVP_ENCODE_CTX_free(ctx);

    return plaintext_len;
}