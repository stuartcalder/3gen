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
	Password_Generator{ argc, argv };
	return EXIT_SUCCESS;
}
