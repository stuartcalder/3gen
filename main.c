#include "threegen.h"

int main (int argc, char** argv) {
	BASE_OPENBSD_UNVEIL(NULL, NULL);
	BASE_OPENBSD_PLEDGE("stdio tty rpath", NULL);
	Threegen tg = {0};
	threegen(argc, argv, &tg);
	return EXIT_SUCCESS;
}
