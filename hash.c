/*
  +----------------------------------------------------------------------+
  | hash.c: hashing functions (hashing library for IBM DB2)              |
  +----------------------------------------------------------------------+
  | Copyright (c) 2007-2018 Helmut K. C. Tessarek                        |
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

#include <stdio.h>
#include <string.h>
#include <apr_base64.h>
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

int is_valid_salt(const char *salt)
{
	while (*salt)
	{
		if (!((*salt >= 'a' && *salt <= 'z') || (*salt >= 'A' && *salt <= 'Z') || (*salt >= '0' && *salt <= '9') || *salt == '.' || *salt == '/'))
			return FALSE;
		salt++;
	}
	return TRUE;
}

int supported(int alg)
{
#if APR_HAVE_CRYPT_H
	char salt[16+3];
	char *answer;

	if (alg != ALG_SHA256 && alg != ALG_SHA512)
		return FALSE;

	salt[0] = '$';
	salt[1] = alg +'0';
	salt[2] = '$';
	salt[3] = '\0';

	strcat(salt, "tessarek");
	answer = crypt("tessarek", salt);

	if (alg == ALG_SHA256 && strcmp(answer, "$5$tessarek$qeDSegIyJHHxL8NQkuNa.MdFOcQuB7OlgASFBTWNsg9") == 0)
		return TRUE;

	if (alg == ALG_SHA512 && strcmp(answer, "$6$tessarek$asevmwEuZSZqp7x3tbQBR/4o/DpAFVlfDiJjoRNbm8/iTHdF7nlJeykFVmqRYw27OHp9qyH2C2yp3UL47U.4W0") == 0)
		return TRUE;
#endif

	return FALSE;
}

void sha256_base64(const char *clear, int len, char *out)
{
	int l;
	SHA256_CTX context;
	apr_byte_t digest[SHA256_DIGEST_LENGTH];

	apr__SHA256_Init(&context);
	apr__SHA256_Update(&context, (const unsigned char *)clear, len);
	apr__SHA256_Final(digest, &context);

	apr_cpystrn(out, APR_SHA256PW_ID, APR_SHA256PW_IDLEN + 1);

	l = apr_base64_encode_binary(out + APR_SHA256PW_IDLEN, digest, sizeof(digest));
	out[l + APR_SHA256PW_IDLEN] = '\0';
}

char* mk_hash(int alg, const char *passwd, const char *mysalt)
{
	char *result;
	char cpw[120];
	char salt[16];
	char finalsalt[16+3];
	int ret = 0;

	int cost = 5;

	unsigned char digest[APR_MD5_DIGESTSIZE];
	apr_md5_ctx_t context;
	char md5str[33];

	SHA256_CTX context256;
	apr_byte_t digest256[SHA256_DIGEST_LENGTH];
	char sha256str[65];

	apr_sha1_ctx_t context1;
	apr_byte_t digest1[APR_SHA1_DIGESTSIZE];
	char sha1str[41];

	int i;
	char *r;

	int MYSALT = 0;

	cpw[0] = '\0';

	if (mysalt != NULL && strlen(mysalt) == 8)
	{
		MYSALT = 1;
	}

	switch (alg)
	{
#if BCRYPT_ALGO_SUPPORTED
		case ALG_BCRYPT:
		default:
			ret = apr_generate_random_bytes((unsigned char*)salt, 16);
			if (ret != 0)
				break;

			ret = apr_bcrypt_encode(passwd, cost, (unsigned char*)salt, 16, cpw, sizeof(cpw));

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

		case ALG_SHA256:
		case ALG_SHA512:
			if (!supported(alg))
				break;
			ret = generate_salt(salt, 8);
			if (ret != 0)
				break;

			finalsalt[0] = '$';
			finalsalt[1] = alg +'0';
			finalsalt[2] = '$';
			finalsalt[3] = '\0';
			if (MYSALT)
			{
				strcat(finalsalt, mysalt);
			}
			else
			{
				strcat(finalsalt, salt);
			}

			apr_cpystrn(cpw, (char *)crypt(passwd, finalsalt), sizeof(cpw) - 1);
			break;
#endif

		case ALG_PHPMD5:
			md5str[0] = '\0';

			apr_md5_init(&context);
			apr_md5_update(&context, passwd, strlen(passwd));
			apr_md5_final(digest, &context);
			for (i = 0, r = md5str; i < APR_MD5_DIGESTSIZE; i++, r += 2)
			{
				sprintf(r, "%02x", digest[i]);
			}
			*r = '\0';

			apr_cpystrn(cpw, md5str, sizeof(md5str));
			memset(md5str, '\0', strlen(md5str));
			break;

		case ALG_SHA256HEX:
			sha256str[0] = '\0';

			apr__SHA256_Init(&context256);
			apr__SHA256_Update(&context256, (const apr_byte_t *)passwd, strlen(passwd));
			apr__SHA256_Final(digest256, &context256);
			for (i = 0, r = sha256str; i < SHA256_DIGEST_LENGTH; i++, r += 2)
			{
				sprintf(r, "%02x", digest256[i]);
			}
			*r = '\0';

			apr_cpystrn(cpw, sha256str, sizeof(sha256str));
			memset(sha256str, '\0', strlen(sha256str));
			break;

		case ALG_SHA1HEX:
			sha1str[0] = '\0';

			apr_sha1_init(&context1);
			apr_sha1_update(&context1, passwd, strlen(passwd));
			apr_sha1_final(digest1, &context1);
			for (i = 0, r = sha1str; i < APR_SHA1_DIGESTSIZE; i++, r += 2)
			{
				sprintf(r, "%02x", digest1[i]);
			}
			*r = '\0';

			apr_cpystrn(cpw, sha1str, sizeof(sha1str));
			memset(sha1str, '\0', strlen(sha1str));
			break;
	}

	result = (char*)malloc((strlen(cpw)+1)*sizeof(char));
	apr_cpystrn(result, cpw, sizeof(cpw));
	memset(cpw, '\0', strlen(cpw));

	return result;
}

int validate_hash(const char *password, const char *hash)
{
	apr_status_t status;
	char *tmphash, *result;

	if (!strncmp(hash, APR_SHA256PW_ID, APR_SHA256PW_IDLEN))
	{
		tmphash = mk_hash(ALG_APSHA256, password, NULL);

		if (apr_strnatcmp(hash, tmphash) == 0)
		{
			free(tmphash);
			return TRUE;
		}
		else
		{
			free(tmphash);
			return FALSE;
		}
	}

	if (strlen(hash) == 32 && (hash[0] != '$'))
	{
		tmphash = mk_hash(ALG_PHPMD5, password, NULL);

		if (apr_strnatcmp(hash, tmphash) == 0)
		{
			free(tmphash);
			return TRUE;
		}
		else
		{
			free(tmphash);
			return FALSE;
		}
	}

	if (strlen(hash) == 64 && (hash[0] != '$'))
	{
		tmphash = mk_hash(ALG_SHA256HEX, password, NULL);

		if (apr_strnatcmp(hash, tmphash) == 0)
		{
			free(tmphash);
			return TRUE;
		}
		else
		{
			free(tmphash);
			return FALSE;
		}
	}

	if (strlen(hash) == 40 && (hash[0] != '$'))
	{
		tmphash = mk_hash(ALG_SHA1HEX, password, NULL);

		if (apr_strnatcmp(hash, tmphash) == 0)
		{
			free(tmphash);
			return TRUE;
		}
		else
		{
			free(tmphash);
			return FALSE;
		}
	}

	status = apr_password_validate(password, hash);

	if (status == APR_SUCCESS)
	{
		return TRUE;
	}
#ifndef WIN32
	else
	{
		// maybe a different encrypted password (glibc2 crypt)?
		result = crypt(password, hash);
		if (result != NULL)
		{
			if (strcmp(hash, result) == 0)
			{
				return TRUE;
			}
			else
			{
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}
#endif
}
