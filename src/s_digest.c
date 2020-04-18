//
// Created by silentvoid on 4/17/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#include "s_digest.h"
#include "s_openssl.h"

int s_digest(char *digest_mode, unsigned char *data, size_t data_len, unsigned char **digest) {
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

    EVP_MD_CTX *mdctx;
    unsigned int digest_len;

    if((mdctx = EVP_MD_CTX_new()) == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new() failure\n");
        return -1;
    }

    if(1 != EVP_DigestInit_ex(mdctx, evp_digest, NULL)) {
        fprintf(stderr, "EVP_DigestInit_ex() failure\n");
        return -1;
    }

    if(1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        fprintf(stderr, "EVP_DigestUpdate() failure");
        return -1;
    }

    if((*digest = malloc(EVP_MD_size(evp_digest)+1)) == NULL) {
        free(*digest);
        fprintf(stderr, "malloc() failure\n");
        return -1;
    }

    if(1 != EVP_DigestFinal_ex(mdctx, *digest, &digest_len)) {
        free(*digest);
        fprintf(stderr, "EVP_DigestFinal_ex() failure");
        return -1;
    }

    EVP_MD_CTX_free(mdctx);

    return (int)digest_len;
}

EVP_MD_CTX * s_digest_init(char *digest_mode) {
    const EVP_MD *evp_digest;
    if (strcmp(digest_mode, "sha1") == 0) {
        evp_digest = EVP_sha1();
    } else if (strcmp(digest_mode, "sha256") == 0) {
        evp_digest = EVP_sha256();
    } else if (strcmp(digest_mode, "sha512") == 0) {
        evp_digest = EVP_sha512();
    } else {
        fprintf(stderr, "Unknown digest mode\n");
        return NULL;
    }

    EVP_MD_CTX *mdctx;

    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new() failure\n");
        return NULL;
    }

    if (1 != EVP_DigestInit_ex(mdctx, evp_digest, NULL)) {
        fprintf(stderr, "EVP_DigestInit_ex() failure\n");
        return NULL;
    }

    return mdctx;
}

EVP_MD_CTX * s_digest_update(EVP_MD_CTX *mdctx, unsigned char *data, size_t data_len) {
    if (1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        fprintf(stderr, "EVP_DigestUpdate() failure");
        return NULL;
    }
    return mdctx;
}

int s_digest_digest(EVP_MD_CTX *mdctx, char *digest_mode, unsigned char **digest) {
    const EVP_MD *evp_digest;
    if (strcmp(digest_mode, "sha1") == 0) {
        evp_digest = EVP_sha1();
    } else if (strcmp(digest_mode, "sha256") == 0) {
        evp_digest = EVP_sha256();
    } else if (strcmp(digest_mode, "sha512") == 0) {
        evp_digest = EVP_sha512();
    } else {
        fprintf(stderr, "Unknown digest mode\n");
        return -1;
    }

    unsigned int digest_len;

    if((*digest = malloc(EVP_MD_size(evp_digest)+1)) == NULL) {
        free(*digest);
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "malloc() failure\n");
        return -1;
    }

    if(1 != EVP_DigestFinal_ex(mdctx, *digest, &digest_len)) {
        free(*digest);
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "EVP_DigestFinal_ex() failure");
        return -1;
    }
    EVP_MD_CTX_free(mdctx);

    return (int)digest_len;
}
