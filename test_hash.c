#include <stdio.h>
#include <string.h>
#include "hash.h"

int main( int argc, char *argv[] )
{
	char clear[4096+1];
	char *hash;
	char *salt = NULL;

	if (argc < 2 || strlen(argv[1]) > 4096)
	{
		strcpy(clear, "test");
	}
	else
	{
		strcpy(clear, argv[1]);
	}

	if (argc >= 3 && strlen(argv[2]) == 8)
	{
		salt = argv[2];
		if( !is_valid_salt(salt) )
		{
			printf("Error: salt must be a string chosen from the set [a–zA–Z0–9./].\n");
			exit(1);
		}
	}
	if (argc >= 3 && strlen(argv[2]) != 8)
	{
		printf("Error: salt must be exactly 8 characters long.\n");
		exit(1);
	}

	printf( "\nUsing word '%s' (without the quotes)\n", clear );

	hash = mk_hash( ALG_PHPMD5, clear, NULL );
	printf( "\nphp_md5     -> %s", hash);
	free(hash);

	hash = mk_hash( ALG_APMD5, clear, NULL );
	printf( "\napr_md5     -> %s", hash);
	free(hash);

	hash = mk_hash( ALG_CRYPT, clear, NULL );
	printf( "\napr_crypt   -> %s", hash);
	free(hash);

	hash = mk_hash( ALG_APSHA, clear, NULL );
	printf( "\napr_sha1    -> %s", hash);
	free(hash);

	hash = mk_hash( ALG_APSHA256, clear, NULL );
	printf( "\napr_sha256  -> %s", hash);
	free(hash);

	if (supported(ALG_SHA256))
	{
		hash = mk_hash( ALG_SHA256, clear, salt );
		printf( "\nsha256      -> %s", hash);
		free(hash);
	}

	if (supported(ALG_SHA256))
	{
		hash = mk_hash( ALG_SHA512, clear, salt );
		printf( "\nsha512      -> %s", hash);
		free(hash);
	}

	hash = mk_hash( ALG_SHA256HEX, clear, NULL );
	printf( "\nsha256_hex  -> %s", hash);
	free(hash);

#if BCRYPT_ALGO_SUPPORTED
	hash = mk_hash( ALG_BCRYPT, clear, NULL );
	printf( "\nbcrypt      -> %s", hash);
	free(hash);
#endif

	printf("\n\n");

	return 0;
}
