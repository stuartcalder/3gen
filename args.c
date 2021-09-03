#include "args.h"
#include <Base/strings.h>

#define R_(p) p BASE_RESTRICT
#define PROC_(name)	int name##_argproc(const int argc, R_(char**) argv, const int off, R_(void*) v)
#define CTX_		((Threegen*)v)

#ifdef THREEGEN_EXTERN_STRICT_ARG_PROCESSING
#	define HANDLE_INVALID_ARG_(arg) Base_errx("Error: Invalid argument (%s)\n", arg)
#else
#	define HANDLE_INVALID_ARG_(arg) /* Nil */
#endif

PROC_(all) {
	CTX_->flags |= (THREEGEN_USE_LCASE|THREEGEN_USE_UCASE|
			THREEGEN_USE_SYMBOLS|THREEGEN_USE_DIGITS);
	return Base_1opt(argv[0][off]);
}
PROC_(digit) {
	CTX_->flags |= THREEGEN_USE_DIGITS;
	return Base_1opt(argv[0][off]);
}
PROC_(entropy) {
	CTX_->flags |= THREEGEN_GET_ENTROPY;
	return Base_1opt(argv[0][off]);
}
PROC_(format) {
	CTX_->flags |= THREEGEN_USE_FORMATTING;
	return Base_1opt(argv[0][off]);
}
PROC_(help) {
	print_help();
	exit(EXIT_SUCCESS);
	return 0;
}
PROC_(lower) {
	CTX_->flags |= THREEGEN_USE_LCASE;
	return Base_1opt(argv[0][off]);
}

#define ERR_MIN_PW_SIZE_PROMPT_ "Error: Minimum password size is 1 character.\n"
#define ERR_MAX_PW_SIZE_PROMPT_ "Error: Maximum password size is " BASE_STRINGIFY(THREEGEN_MAX_PW_SIZE) " characters.\n"
PROC_(password_size) {
	Base_Arg_Parser bap;
	Base_Arg_Parser_init(&bap, argv[0], argc, argv);
	if (bap.to_read) {
		Base_assert_msg((bap.size >= 1), ERR_MIN_PW_SIZE_PROMPT_);
		Base_assert_msg((bap.size <= 3), ERR_MAX_PW_SIZE_PROMPT_);
		char* const tmp = (char*)Base_malloc_or_die(bap.size + 1);
		memcpy(tmp, bap.to_read, bap.size + 1);
		int n_digits = Base_shift_left_digits(tmp, bap.size);
		Base_assert_msg((n_digits >= 1), ERR_MIN_PW_SIZE_PROMPT_);
		Base_assert_msg((n_digits <= 3), ERR_MAX_PW_SIZE_PROMPT_);
		int size = atoi(tmp);
		Base_assert_msg((size >= 1), ERR_MIN_PW_SIZE_PROMPT_);
		Base_assert_msg((size <= THREEGEN_MAX_PW_SIZE), ERR_MAX_PW_SIZE_PROMPT_);
		CTX_->requested_pw_size = size;
		free(tmp);
		return bap.consumed;
	}
	return 0;
}
PROC_(symbol) {
	CTX_->flags |= THREEGEN_USE_SYMBOLS;
	return Base_1opt(argv[0][off]);
}
PROC_(upper) {
	CTX_->flags |= THREEGEN_USE_UCASE;
	return Base_1opt(argv[0][off]);
}
