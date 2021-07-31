#ifndef THREEGEN_ARGS_H
#define THREEGEN_ARGS_H
#include "threegen.h"

#define R_(ptr) ptr BASE_RESTRICT
BASE_BEGIN_DECLS

Base_Arg_Handler_f* short_parser (const char*);
Base_Arg_Handler_f* long_parser (const char*);
Base_Arg_Handler_f* floating_parser (const char*);
Base_Arg_Parser_f*  arg_processor (const char*, void* BASE_RESTRICT);

#define PROTOTYPE_HANDLER_(pfx) \
  void pfx##_handler (char**, const int, void* BASE_RESTRICT)
#define EQUIVALENT_HANDLER_(ptrPfx, funcPfx) \
  static Base_Arg_Handler_f* const ptrPfx##_handler = funcPfx##_handler

PROTOTYPE_HANDLER_(h);
EQUIVALENT_HANDLER_(help, h);
PROTOTYPE_HANDLER_(l);
EQUIVALENT_HANDLER_(lower, l);
PROTOTYPE_HANDLER_(u);
EQUIVALENT_HANDLER_(upper, u);
PROTOTYPE_HANDLER_(d);
EQUIVALENT_HANDLER_(digit, d);
PROTOTYPE_HANDLER_(s);
EQUIVALENT_HANDLER_(symbol, s);
PROTOTYPE_HANDLER_(a);
EQUIVALENT_HANDLER_(all, a);
PROTOTYPE_HANDLER_(f);
EQUIVALENT_HANDLER_(format, f);
PROTOTYPE_HANDLER_(E);
EQUIVALENT_HANDLER_(entropy, E);
PROTOTYPE_HANDLER_(password_size);
#undef PROTOTYPE_EQUIVALENT_HANDLER_
#undef PROTOTYPE_HANDLER_

BASE_END_DECLS
#undef R_

#endif /* ~ THREEGEN_ARGS_H */
