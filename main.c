#include "threegen.h"

int main (int argc, char** argv) {
	BASE_OPENBSD_UNVEIL(NULL, NULL);
	BASE_OPENBSD_PLEDGE("stdio tty rpath", NULL);
	Threegen tg = THREEGEN_NULL_LITERAL;
	threegen(argc, argv, &tg);
	return EXIT_SUCCESS;
}
