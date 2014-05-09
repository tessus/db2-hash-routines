#include <stdio.h>
#include <string.h>
#include "hash.h"

int main( void )
{
	char clear[6];
	char *hash;

	strcpy(clear, "test");

	printf( "\nUsing word 'test' (without the quotes)\n" );

	hash = mk_hash( clear, ALG_PHPMD5 );
	printf( "\nphp_md5     -> %s", hash);

	hash = mk_hash( clear, ALG_APMD5 );
	printf( "\napr_md5     -> %s", hash);

	hash = mk_hash( clear, ALG_CRYPT );
	printf( "\napr_crypt   -> %s", hash);

	hash = mk_hash( clear, ALG_APSHA );
	printf( "\napr_sha1    -> %s", hash);

	hash = mk_hash( clear, ALG_APSHA256 );
	printf( "\napr_sha256  -> %s", hash);

#if BCRYPT_ALGO_SUPPORTED
	hash = mk_hash( clear, ALG_BCRYPT );
	printf( "\nbcrypt      -> %s", hash);
#endif

	printf("\n\n");

	free(hash);

	return 0;
}
