//
// Created by silentvoid on 4/17/20.
// Copyright (c) 2020 SilentVoid. All rights reserved.
//

#ifndef SILENT_OPENSSL_S_CURVE_H
#define SILENT_OPENSSL_S_CURVE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>

int s_curve_shared_secret(char *key_algorithm, unsigned char *public_key, size_t public_key_len, unsigned char *private_key, size_t private_key_len, unsigned char **shared_secret);

#endif //SILENT_OPENSSL_S_CURVE_H
