#include "threegen.h"

int main (int argc, char** argv) {
	BASE_OPENBSD_UNVEIL(BASE_NULL, BASE_NULL);
	BASE_OPENBSD_PLEDGE("stdio tty rpath", BASE_NULL);
	Threegen tg = THREEGEN_NULL_LITERAL;
	threegen(argc, argv, &tg);
	return EXIT_SUCCESS;
}
