/* Copyright (c) 2020 Stuart Steven Calder
 * See the accompanying LICENSE file for licensing information.
 */
#include "password_generator.hh"

#include <cstdlib>
#include <cstdio>

#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/skein_csprng.hh>

#ifdef __OpenBSD__
/* Only OpenBSD systems */
#	include <unistd.h> // Include unistd.h for unveil() and pledge()
#	ifndef OPENBSD_UNVEIL
#		define OPENBSD_UNVEIL(path,permissions) \
		if (unveil( path, permissions ) != 0) \
			errx( "Failed to unveil() " #path "\n" )
#	else
#		error 'OPENBSD_UNVEIL Already Defined'
#	endif /* ifndef OPENBSD_UNVEIL */
#else
/* All non-OpenBSD systems */
#endif /* #ifdef __OpenBSD__*/

using namespace ssc;
int main (int const argc, char const *argv[])
{

	OPENBSD_UNVEIL( "/usr", "rx" );

	Password_Generator{ argc, argv };
	return EXIT_SUCCESS;
}

#undef OPENBSD_UNVEIL
