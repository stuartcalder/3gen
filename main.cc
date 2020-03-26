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

using namespace ssc;
int main (int const argc, char const *argv[])
{

	_OPENBSD_UNVEIL( "/usr", "rx" );
	_OPENBSD_UNVEIL( nullptr, nullptr );

	Password_Generator{ argc, argv };
	return EXIT_SUCCESS;
}
