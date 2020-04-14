//
// Created by silentvoid on 4/14/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#ifndef SILENT_OPENSSL_S_AES_H
#define SILENT_OPENSSL_S_AES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCKSIZE 16

int aes_encrypt(char *aes_mode, unsigned char *plaintext, size_t plaintext_len, unsigned char *key, unsigned char *iv, unsigned char **ciphertext);
int aes_decrypt(char *aes_mode, unsigned char *ciphertext, size_t ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char **plaintext);

#endif //SILENT_OPENSSL_S_AES_H
