#ifndef THREEGEN_COMMANDLINEARG_H
#define THREEGEN_COMMANDLINEARG_H
#include "Threegen.h"

#define R_          SSC_RESTRICT
#define PROC_(name) int name##_argproc(const int argc, char** R_ argv, const int off, void* R_ v)
SSC_BEGIN_C_DECLS

PROC_(all);
PROC_(digit);
PROC_(entropy);
PROC_(format);
PROC_(help);
PROC_(lower);
PROC_(password_size);
PROC_(symbol);
PROC_(upper);

SSC_END_C_DECLS
#undef PROC_
#undef R_

#endif
