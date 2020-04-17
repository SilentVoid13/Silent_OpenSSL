//
// Created by silentvoid on 4/17/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#ifndef SILENT_OPENSSL_S_DIGEST_H
#define SILENT_OPENSSL_S_DIGEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdarg.h>

#include "s_openssl.h"

int s_digest(char *digest_mode, unsigned char *data, size_t data_len, unsigned char **digest);

EVP_MD_CTX * s_digest_init(char *digest_mode);
EVP_MD_CTX * s_digest_update(EVP_MD_CTX *mdctx, unsigned char *data, size_t data_len);
int s_digest_digest(EVP_MD_CTX *mdctx, char *digest_mode, unsigned char **digest);

#endif //SILENT_OPENSSL_S_DIGEST_H
