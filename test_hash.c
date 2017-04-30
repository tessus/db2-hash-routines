#include <stdio.h>
#include <string.h>
#include "hash.h"

int main( int argc, char *argv[] )
{
	char clear[4096+1];
	char *hash;

	if (argc < 2 || strlen(argv[1]) > 4096)
	{
		strcpy(clear, "test");
	}
	else
	{
		strcpy(clear, argv[1]);
	}

	printf( "\nUsing word '%s' (without the quotes)\n", clear );

	hash = mk_hash( ALG_PHPMD5, clear );
	printf( "\nphp_md5     -> %s", hash);
	free(hash);

	hash = mk_hash( ALG_APMD5, clear );
	printf( "\napr_md5     -> %s", hash);
	free(hash);

	hash = mk_hash( ALG_CRYPT, clear );
	printf( "\napr_crypt   -> %s", hash);
	free(hash);

	hash = mk_hash( ALG_APSHA, clear );
	printf( "\napr_sha1    -> %s", hash);
	free(hash);

	hash = mk_hash( ALG_APSHA256, clear );
	printf( "\napr_sha256  -> %s", hash);
	free(hash);

	if (supported(ALG_SHA256))
	{
		hash = mk_hash( ALG_SHA256, clear );
		printf( "\nsha256      -> %s", hash);
		free(hash);
	}

	if (supported(ALG_SHA256))
	{
		hash = mk_hash( ALG_SHA512, clear );
		printf( "\nsha512      -> %s", hash);
		free(hash);
	}

#if BCRYPT_ALGO_SUPPORTED
	hash = mk_hash( ALG_BCRYPT, clear );
	printf( "\nbcrypt      -> %s", hash);
	free(hash);
#endif

	printf("\n\n");

	return 0;
}
