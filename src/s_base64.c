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

int s_base64_encode(const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext) {
    // Max size with padding of 2
    size_t ciphertext_len = 4 * ((plaintext_len+2)/3);
    int len;

    *ciphertext = malloc(ciphertext_len + 2);
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

int s_base64_decode(const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **plaintext, int padded) {
    unsigned char *ciphertext_padded;
    size_t ciphertext_padded_len = ciphertext_len;
    if(!padded) {
        ciphertext_padded = malloc(ciphertext_padded_len + 5);
        if(ciphertext_padded == NULL) {
            fprintf(stderr, "malloc() failure\n");
            return -1;
        }
        memcpy(ciphertext_padded, ciphertext, ciphertext_len);

        size_t padding_size = ciphertext_len + (ciphertext_len % 4);
        for(int i = ciphertext_len; i < (int)padding_size; i++) {
            ciphertext_padded[i] = '=';
            ciphertext_padded_len += 1;
        }
    }
    else {
        ciphertext_padded = (unsigned char *)ciphertext;
    }

    size_t plaintext_len = ciphertext_padded_len;
    int len;

    *plaintext = malloc(plaintext_len + 2);
    if(*plaintext == NULL) {
        if(ciphertext_padded != ciphertext)
            free(ciphertext_padded);
        free(*plaintext);
        fprintf(stderr, "malloc() failure\n");
        return -1;
    }
    (*plaintext)[plaintext_len] = '\0';

    EVP_ENCODE_CTX *ctx;
    if(!(ctx = EVP_ENCODE_CTX_new())) {
        if(ciphertext_padded != ciphertext)
            free(ciphertext_padded);
        free(*plaintext);
        fprintf(stderr, "EVP_ENCODE_CTX_new() failure\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_DecodeInit(ctx);

    if(EVP_DecodeUpdate(ctx, *plaintext, &len, ciphertext_padded, ciphertext_padded_len) == -1) {
        if(ciphertext_padded != ciphertext)
            free(ciphertext_padded);
        free(*plaintext);
        fprintf(stderr, "EVP_DecodeUpdate() failure\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len = len;
    if(ciphertext_padded != ciphertext)
        free(ciphertext_padded);

    if(EVP_DecodeFinal(ctx, (*plaintext) + len, &len) == -1) {
        free(*plaintext);
        fprintf(stderr, "EVP_DecodeFinal() failure\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    plaintext_len += len;
    (*plaintext)[plaintext_len] = '\0';
    EVP_ENCODE_CTX_free(ctx);

    return plaintext_len;
}
