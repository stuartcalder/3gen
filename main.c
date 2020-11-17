#include "threegen.h"

int
main (int argc, char ** argv) {
	SHIM_OPENBSD_UNVEIL ("/usr", "r");
	SHIM_OPENBSD_UNVEIL (NULL, NULL);
	SHIM_OPENBSD_PLEDGE ("stdio tty", NULL);
	Threegen tg = THREEGEN_NULL_INIT;
	threegen( argc, argv, &tg );

	return EXIT_SUCCESS;
}
