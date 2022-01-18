#ifndef THREEGEN_ARGS_H
#define THREEGEN_ARGS_H
#include "threegen.h"

#define R_(p)		p BASE_RESTRICT
#define PROC_(name)	int name##_argproc(const int argc, R_(char**) argv, const int off, R_(void*) v)
BASE_BEGIN_C_DECLS
PROC_(all);
PROC_(digit);
PROC_(entropy);
PROC_(format);
PROC_(help);
PROC_(lower);
PROC_(password_size);
PROC_(symbol);
PROC_(upper);
BASE_END_C_DECLS
#undef PROC_
#undef R_

#endif /* ~ THREEGEN_ARGS_H */
