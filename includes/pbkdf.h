//
// Created by silentvoid on 4/14/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#ifndef SILENT_OPENSSL_PBKDF_H
#define SILENT_OPENSSL_PBKDF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int pbkdf2_hmac_derive(const char *password, size_t password_len, const unsigned char *salt, size_t salt_len, size_t iterations, char *digest_mode, unsigned char *output_key, size_t output_key_len);

#endif //SILENT_OPENSSL_PBKDF_H
