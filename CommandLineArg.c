#include "CommandLineArg.h"
#include <SSC/String.h>

#define R_          SSC_RESTRICT
#define PROC_(name) int name##_argproc(const int argc, char** R_ argv, const int off, void* R_ v)
#define CTX_        ((Threegen*)v)

#ifdef THREEGEN_EXTERN_STRICT_ARG_PROCESSING
 #define HANDLE_INVALID_ARG_(arg) SSC_errx("Error: Invalid argument (%s)\n", arg)
#else
 #define HANDLE_INVALID_ARG_(arg) /* Nil */
#endif

PROC_(all)
{
  CTX_->flags |= (THREEGEN_USE_LCASE | THREEGEN_USE_UCASE | THREEGEN_USE_SYMBOLS | THREEGEN_USE_DIGITS);
  return SSC_1opt(argv[0][off]);
}

PROC_(digit)
{
  CTX_->flags |= THREEGEN_USE_DIGITS;
  return SSC_1opt(argv[0][off]);
}

PROC_(entropy)
{
  CTX_->flags |= THREEGEN_GET_ENTROPY;
  return SSC_1opt(argv[0][off]);
}

PROC_(format)
{
  CTX_->flags |= THREEGEN_USE_FORMATTING;
  return SSC_1opt(argv[0][off]);
}

PROC_(help)
{
  print_help();
  exit(EXIT_SUCCESS);
  return 0;
}

PROC_(lower)
{
  CTX_->flags |= THREEGEN_USE_LCASE;
  return SSC_1opt(argv[0][off]);
}

#define ERR_MIN_PW_SIZE_PROMPT_ "Error: Minimum password size is 1 character.\n"
#define ERR_MAX_PW_SIZE_PROMPT_ "Error: Maximum password size is " SSC_STRINGIFY(THREEGEN_MAX_PW_SIZE) " characters.\n"

PROC_(password_size)
{
  SSC_ArgParser ap;
  SSC_ArgParser_init(&ap, argv[0], argc, argv);
  if (ap.to_read) {
    SSC_assertMsg((ap.size >= 1), ERR_MIN_PW_SIZE_PROMPT_);
    SSC_assertMsg((ap.size <= 3), ERR_MAX_PW_SIZE_PROMPT_);
    char* const tmp = (char*)SSC_mallocOrDie(ap.size + 1);
    memcpy(tmp, ap.to_read, ap.size + 1);
    int n_digits = SSC_Cstr_shiftDigitsToFront(tmp, ap.size);
    SSC_assertMsg((n_digits >= 1), ERR_MIN_PW_SIZE_PROMPT_);
    SSC_assertMsg((n_digits <= 3), ERR_MAX_PW_SIZE_PROMPT_);
    int size = atoi(tmp);
    SSC_assertMsg((size >= 1), ERR_MIN_PW_SIZE_PROMPT_);
    SSC_assertMsg((size <= THREEGEN_MAX_PW_SIZE), ERR_MAX_PW_SIZE_PROMPT_);
    CTX_->requested_pw_size = size;
    free(tmp);
    return ap.consumed;
  }
  return 0;
}

PROC_(symbol)
{
  CTX_->flags |= THREEGEN_USE_SYMBOLS;
  return SSC_1opt(argv[0][off]);
}

PROC_(upper)
{
  CTX_->flags |= THREEGEN_USE_UCASE;
  return SSC_1opt(argv[0][off]);
}
