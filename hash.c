/*
  +----------------------------------------------------------------------+
  | hash.c: hashing functions (hashing library for IBM DB2)              |
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

#include <stdio.h>
#include <string.h>
#include "hash.h"
#include "sha2.h"

static int generate_salt(char *s, size_t size)
{
	unsigned char rnd[32];
	static const char itoa64[] =
		"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	apr_size_t n;
	unsigned int val = 0, bits = 0;
	apr_status_t rv;

	n = (size * 6 + 7)/8;
	if (n > sizeof(rnd))
	{
		return -1;
	}
	rv = apr_generate_random_bytes(rnd, n);
	if (rv)
	{
		return -1;
	}
	n = 0;
	while (size > 0)
	{
		if (bits < 6)
		{
			val |= (rnd[n++] << bits);
			bits += 8;
		}
		*s++ = itoa64[val & 0x3f];
		size--;
		val >>= 6;
		bits -= 6;
	}
	*s = '\0';
	return 0;
}

void sha256_base64( const char *clear, int len, char *out )
{
	int l;
	SHA256_CTX context;
	apr_byte_t digest[SHA256_DIGEST_LENGTH];

	apr__SHA256_Init( &context );
	apr__SHA256_Update( &context, clear, len );
	apr__SHA256_Final( digest, &context );

	apr_cpystrn( out, APR_SHA256PW_ID, APR_SHA256PW_IDLEN + 1 );

	l = apr_base64_encode_binary( out + APR_SHA256PW_IDLEN, digest, sizeof(digest) );
	out[l + APR_SHA256PW_IDLEN] = '\0';
}

char* mk_hash( const char *passwd, int alg )
{
	char *result;
	char cpw[120];
	char salt[16];
	int ret = 0;

	int cost = 5;

	unsigned char digest[APR_MD5_DIGESTSIZE];
	apr_md5_ctx_t context;
	char md5str[33];
	int i;
	char *r;

	cpw[0] = '\0';

	switch (alg)
	{
#if BCRYPT_ALGO_SUPPORTED
		case ALG_BCRYPT:
		default:
			ret = apr_generate_random_bytes((unsigned char*)salt, 16);
			if (ret != 0)
				break;

			ret = apr_bcrypt_encode(passwd, cost, (unsigned char*)salt, 16,
								   cpw, sizeof(cpw));
			if (ret != 0)
				break;

			break;
#endif

		case ALG_APSHA256:
			sha256_base64(passwd, strlen(passwd), cpw);
			break;

		case ALG_APSHA:
			apr_sha1_base64(passwd, strlen(passwd), cpw);
			break;

		case ALG_APMD5:
#if !BCRYPT_ALGO_SUPPORTED
		default:
#endif
			ret = generate_salt(salt, 8);
			if (ret != 0)
				break;

			apr_md5_encode((const char *)passwd, (const char *)salt, cpw, sizeof(cpw));
			break;

#if !(defined(WIN32) || defined(NETWARE))
		case ALG_CRYPT:
			ret = generate_salt(salt, 8);
			if (ret != 0)
				break;

			apr_cpystrn(cpw, (char *)crypt(passwd, salt), sizeof(cpw) - 1);
			break;
#endif

		case ALG_PHPMD5:
			md5str[0] = '\0';

			apr_md5_init( &context );
			apr_md5_update( &context, passwd, strlen(passwd) );
			apr_md5_final( digest, &context );
			for( i = 0, r = md5str; i < APR_MD5_DIGESTSIZE; i++, r += 2 )
			{
			sprintf( r, "%02x", digest[i] );
			}
			*r = '\0';

			apr_cpystrn(cpw, md5str, sizeof(md5str));
			break;
	}

	result = (char*)malloc(strlen(cpw)*sizeof(char));
	strcpy( result, cpw );
	memset(cpw, '\0', strlen(cpw));

	return result;
}
