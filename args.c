#include "args.h"
#include <shim/strings.h>

#define STRINGIFY_IMPL_(text) \
	#text
#define STRINGIFY_(text) \
	STRINGIFY_IMPL_ (text)

#ifdef THREEGEN_EXT_STRICT_ARG_PROCESSING
#	define HANDLE_INVALID_ARG_(arg) shim_errx("Error: Invalid argument (%s)\n", arg)
#else
#	define HANDLE_INVALID_ARG_(arg) /* Nil */
#endif

Shim_Arg_Handler_f *
short_parser (char const * str) {
	size_t const str_size = strlen(str);
	switch (str_size) {
		case 2:
			switch (str[1]) {
				case 'h': return h_handler;
				case 'l': return l_handler;
				case 'u': return u_handler;
				case 'd': return d_handler;
				case 's': return s_handler;
				case 'f': return f_handler;
				case 'a': return a_handler;
				case 'E': return E_handler;
			}
	}
	HANDLE_INVALID_ARG_ (str);
	return NULL;
}

#define STR_EQ_(s0, s1) (!strcmp(s0, s1))
#define STR_TO_F_(s, f) if (STR_EQ_(str + 2, s)) return f

Shim_Arg_Handler_f *
long_parser (char const * str) {
	size_t const str_size = strlen(str) - 2;
	switch (str_size) {
		case 3:
			STR_TO_F_("all", all_handler);
			break;
		case 4:
			STR_TO_F_("help", help_handler);
			break;
		case 5:
			STR_TO_F_("lower", lower_handler);
			STR_TO_F_("upper", upper_handler);
			STR_TO_F_("digit", digit_handler);
			break;
		case 6:
			STR_TO_F_("symbol", symbol_handler);
			STR_TO_F_("format", format_handler);
			break;
		case 7:
			STR_TO_F_("entropy", entropy_handler);
			break;
	}
	HANDLE_INVALID_ARG_(str);
	return NULL;
}

Shim_Arg_Handler_f *
floating_parser (char const * discard) {
	return password_size_handler;
}

Shim_Arg_Parser_f *
arg_processor (char const * str, void * SHIM_RESTRICT v_ctx) {
	int type = shim_argtype(str);
	switch (type) {
		case SHIM_ARGTYPE_SHORT: return short_parser;
		case SHIM_ARGTYPE_LONG:  return long_parser;
	}
	return floating_parser;
}

#define HANDLER_IMPL_(name) \
	void \
	name##_handler (char ** str_arr, int const str_cnt, void * SHIM_RESTRICT v_ctx)
#define CTX_ ((Threegen *)v_ctx)

HANDLER_IMPL_(h) { print_help(); exit(EXIT_SUCCESS); }
HANDLER_IMPL_(l) { CTX_->flags |= THREEGEN_USE_LCASE; }
HANDLER_IMPL_(u) { CTX_->flags |= THREEGEN_USE_UCASE; }
HANDLER_IMPL_(d) { CTX_->flags |= THREEGEN_USE_DIGITS; }
HANDLER_IMPL_(s) { CTX_->flags |= THREEGEN_USE_SYMBOLS; }
#define USE_ALL_CHARS_ (THREEGEN_USE_LCASE|THREEGEN_USE_UCASE|THREEGEN_USE_DIGITS|THREEGEN_USE_SYMBOLS)
HANDLER_IMPL_(a) { CTX_->flags |= USE_ALL_CHARS_; }
HANDLER_IMPL_(f) { CTX_->flags |= THREEGEN_USE_FORMATTING; }
HANDLER_IMPL_(E) { CTX_->flags |= THREEGEN_GET_ENTROPY; }

#define ERR_MIN_PW_SIZE_PROMPT_ "Error: Minimum password size is 1 character.\n"
#define ERR_MAX_PW_SIZE_PROMPT_ "Error: Maximum password size is " STRINGIFY_ (THREEGEN_MAX_PW_SIZE) " characters.\n"

HANDLER_IMPL_(password_size) {
	char const * str = *str_arr;
	size_t const str_size = strlen(str);
	shim_assert_msg(str_size >= 1, ERR_MIN_PW_SIZE_PROMPT_);
	shim_assert_msg(str_size <= 3, ERR_MAX_PW_SIZE_PROMPT_);
	char * scratch_str = (char *)shim_enforce_malloc(str_size + 1);
	{
		memcpy(scratch_str, str, str_size + 1);
		int num_digits = shim_shift_left_digits(scratch_str, str_size);
		shim_assert_msg(num_digits >= 1, ERR_MIN_PW_SIZE_PROMPT_);
		shim_assert_msg(num_digits <= 3, ERR_MAX_PW_SIZE_PROMPT_);
		int size = atoi(scratch_str);
		shim_assert_msg(size >= 1, ERR_MIN_PW_SIZE_PROMPT_);
		shim_assert_msg(size <= THREEGEN_MAX_PW_SIZE, ERR_MAX_PW_SIZE_PROMPT_);
		CTX_->requested_pw_size = size;
	}
	free(scratch_str);
}
