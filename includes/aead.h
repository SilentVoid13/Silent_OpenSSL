//
// Created by silentvoid on 4/14/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#ifndef SILENT_OPENSSL_AEAD_H
#define SILENT_OPENSSL_AEAD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCKSIZE 16

int aead_aes_256_gcm_encrypt(unsigned char *plaintext, size_t plaintext_len, unsigned char *aad, size_t aad_len, unsigned char *key, unsigned char *iv, size_t iv_len, unsigned char **ciphertext, unsigned char *tag);
int aead_aes_256_gcm_decrypt(unsigned char *ciphertext, size_t ciphertext_len, unsigned char *aad, size_t aad_len, unsigned char *key, unsigned char *iv, size_t iv_len, unsigned char **plaintext, unsigned char *tag);

#endif //SILENT_OPENSSL_AEAD_H
