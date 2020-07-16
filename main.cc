/* Copyright (c) 2020 Stuart Steven Calder
 * See the accompanying LICENSE file for licensing information.
 */
#include "password_generator.hh"

#include <cstdlib>
#include <cstdio>

#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>

using namespace ssc;
int
main (int const argc, char const *argv[])
{

	SHIM_OPENBSD_UNVEIL ("/usr", "rx");
	SHIM_OPENBSD_UNVEIL (nullptr, nullptr);
	SHIM_OPENBSD_PLEDGE ("stdio rpath tty", nullptr);

	C_Argument_Map c_arg_map{ argc, argv };

	Password_Generator{ c_arg_map };
	return EXIT_SUCCESS;
}
