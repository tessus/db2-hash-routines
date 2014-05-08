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

static void to64(char *s, unsigned long v, int n)
{
	static unsigned char itoa64[] =         /* 0 ... 63 => ASCII - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

	while (--n >= 0)
	{
		*s++ = itoa64[v&0x3f];
		v >>= 6;
	}
}

char* mk_hash( const char *passwd, int alg )
{
	char *result;
	char cpw[120];
	char salt[9];

	unsigned char digest[APR_MD5_DIGESTSIZE];
	apr_md5_ctx_t context;
	char md5str[33];
	int i;
	char *r;

	cpw[0] = '\0';

	switch (alg)
	{

		case ALG_APSHA:
			apr_sha1_base64(passwd,strlen(passwd),cpw);
			break;

		case ALG_APMD5:
		default:
			(void) srand((int) time((time_t *) NULL));
			to64(&salt[0], rand(), 8);
			salt[8] = '\0';

			apr_md5_encode((const char *)passwd, (const char *)salt,
			cpw, sizeof(cpw));
			break;

#if !(defined(WIN32) || defined(NETWARE))
		case ALG_CRYPT:
			(void) srand((int) time((time_t *) NULL));
			to64(&salt[0], rand(), 8);
			salt[8] = '\0';

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

	return result;
}
