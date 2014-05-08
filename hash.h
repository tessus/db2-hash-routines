/*
  +----------------------------------------------------------------------+
  | hash.h: hashing functions include (hashing library for IBM DB2 )     |
  +----------------------------------------------------------------------+
  | Copyright (c) 2007-2014 Helmut K. C. Tessarek                        |
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
  | Website: http://mod-auth-ibmdb2.sourceforge.net                      |
  +----------------------------------------------------------------------+
*/

#ifndef HASH_H
#define HASH_H

#include "apr.h"
#include "apr_md5.h"
#include "apr_sha1.h"
#include "apr_strings.h"
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

#define ALG_CRYPT    1
#define ALG_PHPMD5   2
#define ALG_APMD5    3
#define ALG_APSHA    4
#define ALG_APSHA256 5

static void to64(char *s, unsigned long v, int n);
char* mk_hash( const char *passwd, int alg );

#endif
