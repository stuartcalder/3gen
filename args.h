#ifndef THREEGEN_ARGS_H
#define THREEGEN_ARGS_H
#include "threegen.h"

Shim_Arg_Handler_t *
short_parser (char const *);

Shim_Arg_Handler_t *
long_parser (char const *);

Shim_Arg_Handler_t *
floating_parser (char const *);

Shim_Arg_Parser_t *
arg_processor (char const *, void * SHIM_RESTRICT);

#define PROTOTYPE_HANDLER_(prefix) \
	void \
	prefix##_handler (char **, int const, void * SHIM_RESTRICT)

PROTOTYPE_HANDLER_ (h);
PROTOTYPE_HANDLER_ (help);
PROTOTYPE_HANDLER_ (l);
PROTOTYPE_HANDLER_ (lower);
PROTOTYPE_HANDLER_ (u);
PROTOTYPE_HANDLER_ (upper);
PROTOTYPE_HANDLER_ (d);
PROTOTYPE_HANDLER_ (digit);
PROTOTYPE_HANDLER_ (s);
PROTOTYPE_HANDLER_ (symbol);
PROTOTYPE_HANDLER_ (a);
PROTOTYPE_HANDLER_ (all);
PROTOTYPE_HANDLER_ (f);
PROTOTYPE_HANDLER_ (format);
PROTOTYPE_HANDLER_ (E);
PROTOTYPE_HANDLER_ (entropy);
PROTOTYPE_HANDLER_ (password_size);
#undef PROTOTYPE_HANDLER_

#endif /* ~ THREEGEN_ARGS_H */
