#include "threegen.h"

int
main (int argc, char ** argv) {
	SHIM_OPENBSD_UNVEIL ("/usr", "r");
	SHIM_OPENBSD_UNVEIL (NULL, NULL);
	SHIM_OPENBSD_PLEDGE ("stdio tty", NULL);
	Threegen tg = {
		.character_table = { 0 },
		.use_lcase = false,
		.use_ucase = false,
		.use_digits = false,
		.use_symbols = false,
		.use_formatting = false,
		.supplement_entropy = false,
		.requested_pw_size = false,
		.num_chars = 0
	};
	threegen( argc, argv, &tg );

	return EXIT_SUCCESS;
}
