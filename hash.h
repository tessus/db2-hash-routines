/*
  +----------------------------------------------------------------------+
  | hash.h: hashing functions include (hashing library for IBM DB2)      |
  +----------------------------------------------------------------------+
  | Copyright (c) 2007-2017 Helmut K. C. Tessarek                        |
  +----------------------------------------------------------------------+
  | Licensed under the Apache License, Version 2.0 (the "License"); you  |
  | may not use this file except in compliance with the License. You may |
  | obtain a copy of the License at                                      |
  | http://www.apache.org/licenses/LICENSE-2.0                           |
  |                                                                      |
  | Unless required by applicable law or agreed to in writing, software  |
  | distributed under the License is distributed on an "AS IS" BASIS,    |
  | WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or      |
  | implied. See the License for the specific language governing         |
  | permissions and limitations under the License.                       |
  +----------------------------------------------------------------------+
  | Author: Helmut K. C. Tessarek                                        |
  +----------------------------------------------------------------------+
  | Website: http://tessus.github.io/db2-hash-routines                   |
  +----------------------------------------------------------------------+
*/

#ifndef HASH_H
#define HASH_H

#include "apr.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_strings.h"
#include "apu_version.h"
#include <time.h>

#if APR_HAVE_CRYPT_H
#include <crypt.h>
#endif
#if APR_HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if APR_HAVE_STRING_H
#include <string.h>
#endif
#if APR_HAVE_UNISTD_H
#include <unistd.h>
#endif

#if APU_MAJOR_VERSION == 1 && APU_MINOR_VERSION >= 5
#define BCRYPT_ALGO_SUPPORTED  1
#else
#define BCRYPT_ALGO_SUPPORTED  0
#endif

#define ALG_CRYPT              1
#define ALG_PHPMD5             2
#define ALG_APMD5              3
#define ALG_APSHA              4
#define ALG_SHA256             5
#define ALG_SHA512             6
#define ALG_APSHA256           7
#define ALG_BCRYPT             8
#define ALG_SHA256HEX          9

#define APR_SHA256PW_ID        "{SHA256}"
#define APR_SHA256PW_IDLEN     8

#ifndef FALSE                  // FALSE
#define FALSE 0
#endif
#ifndef TRUE                   // TRUE
#define TRUE (!FALSE)
#endif

static int generate_salt(char *s, size_t size);
int is_valid_salt(const char *salt);
int supported(int alg);
void sha256_base64(const char *clear, int len, char *out);
char* mk_hash(int alg, const char *passwd, const char *mysalt);
int validate_hash(const char *password, const char *hash);

#endif
