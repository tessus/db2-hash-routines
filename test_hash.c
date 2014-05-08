#include <stdio.h>
#include <string.h>
#include "hash.h"

int main( void )
{
	char *hash;

	printf( "\nUsing word Test\n" );

	hash = mk_hash( "Test", ALG_PHPMD5 );
	printf( "\nmd5       -> %s", hash);

	hash = mk_hash( "Test", ALG_APMD5 );
	printf( "\napr_md5   -> %s", hash);

	hash = mk_hash( "Test", ALG_CRYPT );
	printf( "\napr_crypt -> %s", hash);

	hash = mk_hash( "Test", ALG_APSHA );
	printf( "\napr_sha1  -> %s\n\n", hash);

	free(hash);

	return 0;
}
