//
// Created by silentvoid on 4/14/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#ifndef SILENT_OPENSSL_S_BASE64_H
#define SILENT_OPENSSL_S_BASE64_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t calc_base64_length(const unsigned char *b64input);
int s_base64_encode(const unsigned char *plaintext, size_t plaintext_len, unsigned char **ciphertext);
int s_base64_decode(const unsigned char *ciphertext, size_t ciphertext_len, unsigned char **plaintext);

#endif //SILENT_OPENSSL_S_BASE64_H
