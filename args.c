#include "args.h"
#include <shim/strings.h>

#define STRINGIFY_IMPL_(text) \
	#text
#define STRINGIFY_(text) \
	STRINGIFY_IMPL_ (text)

#ifdef THREEGEN_EXT_STRICT_ARG_PROCESSING
#	define HANDLE_INVALID_ARG_(arg) SHIM_ERRX ("Error: Invalid argument (%s)\n", arg)
#else
#	define HANDLE_INVALID_ARG_(arg) /* Nil */
#endif

Shim_Arg_Handler_t *
short_parser (char const * str) {
	size_t const str_size = strlen( str );
	switch( str_size ) {
		case 2:
			switch( str[ 1 ] ) {
				case 'h':
					return h_handler;
				case 'l':
					return l_handler;
				case 'u':
					return u_handler;
				case 'd':
					return d_handler;
				case 's':
					return s_handler;
				case 'f':
					return f_handler;
				case 'a':
					return a_handler;
				case 'E':
					return E_handler;
			}
	}
	HANDLE_INVALID_ARG_ (str);
	return NULL;
}

Shim_Arg_Handler_t *
long_parser (char const * str) {
	size_t const str_size = strlen( str );
	switch( str_size ) {
		case 5:
			if( strcmp( str, "--all" ) == 0 )
				return all_handler;
			break;
		case 6:
			if( strcmp( str, "--help" ) == 0 )
				return help_handler;
			break;
		case 7:
			if( strcmp( str, "--lower" ) == 0 )
				return lower_handler;
			if( strcmp( str, "--upper" ) == 0 )
				return upper_handler;
			if( strcmp( str, "--digit" ) == 0 )
				return digit_handler;
			break;
		case 8:
			if( strcmp( str, "--symbol" ) == 0 )
				return symbol_handler;
			if( strcmp( str, "--format" ) == 0 )
				return format_handler;
			break;
		case 9:
			if( strcmp( str, "--entropy" ) == 0 )
				return entropy_handler;
			break;
	}
	HANDLE_INVALID_ARG_ (str);
	return NULL;
}

Shim_Arg_Handler_t *
floating_parser (char const * discard) {
	return password_size_handler;
}

Shim_Arg_Parser_t *
arg_processor (char const * str, void * SHIM_RESTRICT v_ctx) {
	int type = shim_argtype( str );
	switch( type ) {
		case SHIM_ARGTYPE_SHORT:
			return short_parser;
		case SHIM_ARGTYPE_LONG:
			return long_parser;
	}
	return floating_parser;
}

#define DEFINE_HANDLER_(name) \
	void \
	name##_handler (char ** str_arr, int const str_cnt, void * SHIM_RESTRICT v_ctx)

DEFINE_HANDLER_ (h) {
	print_help();
	exit( EXIT_SUCCESS );
}

DEFINE_HANDLER_ (l) {
	((Threegen *)v_ctx)->use_lcase = true;
}

DEFINE_HANDLER_ (u) {
	((Threegen *)v_ctx)->use_ucase = true;
}

DEFINE_HANDLER_ (d) {
	((Threegen *)v_ctx)->use_digits = true;
}

DEFINE_HANDLER_ (s) {
	((Threegen *)v_ctx)->use_symbols = true;
}

DEFINE_HANDLER_ (a) {
	l_handler( NULL, 0, v_ctx );
	u_handler( NULL, 0, v_ctx );
	d_handler( NULL, 0, v_ctx );
	s_handler( NULL, 0, v_ctx );
}

DEFINE_HANDLER_ (f) {
	((Threegen *)v_ctx)->use_formatting = true;
}

DEFINE_HANDLER_ (E) {
	((Threegen *)v_ctx)->supplement_entropy = true;
}

#define ERR_MIN_PW_SIZE_PROMPT_ "Error: Minimum password size is 1 character.\n"
#define ERR_MAX_PW_SIZE_PROMPT_ "Error: Maximum password size is " STRINGIFY_ (THREEGEN_MAX_PW_SIZE) ".\n"

DEFINE_HANDLER_ (password_size) {
	Threegen * ctx = (Threegen *)v_ctx;
	char const * str = *str_arr;
	size_t const str_size = strlen( str );
	if( str_size < 1 )
		SHIM_ERRX (ERR_MIN_PW_SIZE_PROMPT_);
	if( str_size > 3 )
		SHIM_ERRX (ERR_MAX_PW_SIZE_PROMPT_);
	char * scratch_str = (char *)malloc( str_size + 1 );
	if( !scratch_str )
		SHIM_ERRX (SHIM_ERR_STR_ALLOC_FAILURE);
	{
		memcpy( scratch_str, str, (str_size + 1) );
		int num_digits = shim_shift_left_digits( scratch_str, str_size );
		if( num_digits < 1 )
			SHIM_ERRX (ERR_MIN_PW_SIZE_PROMPT_);
		if( num_digits > 3 )
			SHIM_ERRX (ERR_MAX_PW_SIZE_PROMPT_);
		int size = atoi( scratch_str );
		if( size >= 1 && size <= THREEGEN_MAX_PW_SIZE )
			ctx->requested_pw_size = size;
		else
			SHIM_ERRX ("Error: Invalid password size %d\n", size);
	}
	free( scratch_str );
}



