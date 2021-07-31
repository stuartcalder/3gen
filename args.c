#include "args.h"
#include <Base/strings.h>

#define R_(p) p BASE_RESTRICT

#ifdef THREEGEN_EXTERN_STRICT_ARG_PROCESSING
#	define HANDLE_INVALID_ARG_(arg) Base_errx("Error: Invalid argument (%s)\n", arg)
#else
#	define HANDLE_INVALID_ARG_(arg) /* Nil */
#endif

Base_Arg_Handler_f* short_parser (const char* str) {
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

Base_Arg_Handler_f* long_parser (const char* str) {
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

Base_Arg_Handler_f* floating_parser (const char* discard) {
	return password_size_handler;
}

Base_Arg_Parser_f* arg_processor (const char* str, R_(void*) v_ctx) {
	const int type = Base_argtype(str);
	switch (type) {
		case BASE_ARGTYPE_SHORT: return short_parser;
		case BASE_ARGTYPE_LONG:  return long_parser;
	}
	return floating_parser;
}

#define HANDLER_IMPL_(name) \
  void name##_handler (char ** str_arr, const int str_cnt, void* BASE_RESTRICT v_ctx)
#define CTX_ ((Threegen*)v_ctx)

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
#define ERR_MAX_PW_SIZE_PROMPT_ "Error: Maximum password size is " BASE_STRINGIFY(THREEGEN_MAX_PW_SIZE) " characters.\n"

HANDLER_IMPL_(password_size) {
	const char * const str = *str_arr;
	const size_t str_size = strlen(str);
	Base_assert_msg(str_size >= 1, ERR_MIN_PW_SIZE_PROMPT_);
	Base_assert_msg(str_size <= 3, ERR_MAX_PW_SIZE_PROMPT_);
	char* scratch_str = (char*)Base_malloc_or_die(str_size + 1);
	{
		memcpy(scratch_str, str, str_size + 1);
		int num_digits = Base_shift_left_digits(scratch_str, str_size);
		Base_assert_msg(num_digits >= 1, ERR_MIN_PW_SIZE_PROMPT_);
		Base_assert_msg(num_digits <= 3, ERR_MAX_PW_SIZE_PROMPT_);
		int size = atoi(scratch_str);
		Base_assert_msg(size >= 1, ERR_MIN_PW_SIZE_PROMPT_);
		Base_assert_msg(size <= THREEGEN_MAX_PW_SIZE, ERR_MAX_PW_SIZE_PROMPT_);
		CTX_->requested_pw_size = size;
	}
	free(scratch_str);
}
