//
// Created by silentvoid on 4/17/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#include "s_curve.h"
#include "s_openssl.h"

int s_curve_shared_secret(char *key_algorithm, unsigned char *public_key, size_t public_key_len, unsigned char *private_key, size_t private_key_len, unsigned char **shared_secret) {
    int evp_pkey_mode;

    if(strcmp(key_algorithm, "X25519") == 0) {
        evp_pkey_mode = EVP_PKEY_X25519;
    }
    else if(strcmp(key_algorithm, "X448") == 0) {
        evp_pkey_mode = EVP_PKEY_X448;
    }
    else {
        fprintf(stderr, "Unknown key algorithm\n");
        return -1;
    }

    EVP_PKEY *evp_public_key = NULL;
    EVP_PKEY *evp_private_key = NULL;
    EVP_PKEY_CTX *ctx;
    size_t shared_secret_len;

    if((evp_public_key = EVP_PKEY_new_raw_public_key(evp_pkey_mode, NULL, public_key, public_key_len)) == NULL) {
        fprintf(stderr, "EVP_PKEY_new_raw_private_key() failure\n");
        return -1;
    }

    if((evp_private_key = EVP_PKEY_new_raw_private_key(evp_pkey_mode, NULL, private_key, private_key_len)) == NULL) {
        fprintf(stderr, "EVP_PKEY_new_raw_private_key() failure\n");
        return -1;
    }

    if(!(ctx = EVP_PKEY_CTX_new(evp_private_key, NULL))) {
        fprintf(stderr, "EVP_PKEY_CTX_new() failure\n");
        return -1;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_init() failure\n");
        return -1;
    }

    if (EVP_PKEY_derive_set_peer(ctx, evp_public_key) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive_set_peer() failure\n");
        return -1;
    }

    if (EVP_PKEY_derive(ctx, NULL, &shared_secret_len) <= 0) {
        fprintf(stderr, "EVP_PKEY_derive() failure\n");
        return -1;
    }

    *shared_secret = malloc(shared_secret_len+1);
    if(*shared_secret == NULL) {
        fprintf(stderr, "malloc() failure\n");
        return -1;
    }

    if (EVP_PKEY_derive(ctx, *shared_secret, &shared_secret_len) <= 0){
        fprintf(stderr, "EVP_PKEY_derive() failure\n");
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);

    return shared_secret_len;
}