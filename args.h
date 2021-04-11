#ifndef THREEGEN_ARGS_H
#define THREEGEN_ARGS_H
#include "threegen.h"

SHIM_BEGIN_DECLS

Shim_Arg_Handler_f *
short_parser (char const *);

Shim_Arg_Handler_f *
long_parser (char const *);

Shim_Arg_Handler_f *
floating_parser (char const *);

Shim_Arg_Parser_f *
arg_processor (char const *, void * SHIM_RESTRICT);

#define PROTOTYPE_HANDLER_(prefix) \
	void \
	prefix##_handler (char **, int const, void * SHIM_RESTRICT)
#define PROTOTYPE_EQUIVALENT_HANDLER_(ptr_prefix, func_prefix) \
	static Shim_Arg_Handler_f * const ptr_prefix##_handler = func_prefix##_handler

PROTOTYPE_HANDLER_ (h);
PROTOTYPE_EQUIVALENT_HANDLER_ (help, h);
PROTOTYPE_HANDLER_ (l);
PROTOTYPE_EQUIVALENT_HANDLER_ (lower, l);
PROTOTYPE_HANDLER_ (u);
PROTOTYPE_EQUIVALENT_HANDLER_ (upper, u);
PROTOTYPE_HANDLER_ (d);
PROTOTYPE_EQUIVALENT_HANDLER_ (digit, d);
PROTOTYPE_HANDLER_ (s);
PROTOTYPE_EQUIVALENT_HANDLER_ (symbol, s);
PROTOTYPE_HANDLER_ (a);
PROTOTYPE_EQUIVALENT_HANDLER_ (all, a);
PROTOTYPE_HANDLER_ (f);
PROTOTYPE_EQUIVALENT_HANDLER_ (format, f);
PROTOTYPE_HANDLER_ (E);
PROTOTYPE_EQUIVALENT_HANDLER_ (entropy, E);
PROTOTYPE_HANDLER_ (password_size);
#undef PROTOTYPE_EQUIVALENT_HANDLER_
#undef PROTOTYPE_HANDLER_

SHIM_END_DECLS

#endif /* ~ THREEGEN_ARGS_H */
