#include "Threegen.h"

int main(int argc, char** argv)
{
  SSC_OPENBSD_UNVEIL(SSC_NULL, SSC_NULL);
  SSC_OPENBSD_PLEDGE("stdio tty rpath", SSC_NULL);
  Threegen tg = THREEGEN_NULL_LITERAL;
  threegen(argc, argv, &tg);
  return EXIT_SUCCESS;
}
