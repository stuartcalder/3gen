#ifndef THREEGEN_H
#define THREEGEN_H
/* STD */
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
/* SSC */
#include <SSC/Macro.h>
#include <SSC/Operation.h>
#include <SSC/CommandLineArg.h>
#include <SSC/Terminal.h>
#include <SSC/Error.h>

/* PPQ */
#include <PPQ/CSPRNG.h>
#include <PPQ/Skein512.h>

#define THREEGEN_MAX_PW_SIZE		125
#define THREEGEN_PW_BUF_SIZE		(THREEGEN_MAX_PW_SIZE + 1)
#define THREEGEN_NUM_RAND_WORDS		THREEGEN_PW_BUF_SIZE
#define THREEGEN_NUM_RAND_BYTES		(THREEGEN_NUM_RAND_WORDS * 8)
/* These entropy bytes are going to SSC code with a hard-coded buffer size.
 * Use that hard-coded buffer size to determine the maximum number of bytes
 * we can take from stdin to supplement entropy. */
#define THREEGEN_MAX_ENT_SIZE		120
#define THREEGEN_ENT_BUF_SIZE		(THREEGEN_MAX_ENT_SIZE + 1 + PPQ_THREEFISH512_BLOCK_BYTES)
#define THREEGEN_NUM_LCASE		26
#define THREEGEN_NUM_UCASE		26
#define THREEGEN_NUM_DIGITS		10
#define THREEGEN_NUM_SYMBOLS		32
#define THREEGEN_NUM_ALL_CHARS		(THREEGEN_NUM_LCASE + THREEGEN_NUM_UCASE + THREEGEN_NUM_DIGITS + THREEGEN_NUM_SYMBOLS)
#define THREEGEN_UPPER_LIMIT		(UINT64_MAX - THREEGEN_NUM_ALL_CHARS)
#define THREEGEN_USE_LCASE		UINT8_C(0x01)
#define THREEGEN_USE_UCASE		UINT8_C(0x02)
#define THREEGEN_USE_DIGITS		UINT8_C(0x04)
#define THREEGEN_USE_SYMBOLS		UINT8_C(0x08)
#define THREEGEN_USE_FORMATTING		UINT8_C(0x10)
#define THREEGEN_GET_ENTROPY		UINT8_C(0x20)

typedef struct {
  uint8_t  character_table [THREEGEN_NUM_ALL_CHARS];
  int      requested_pw_size;
  int      num_chars;
  uint8_t  flags;
} Threegen;
#define THREEGEN_NULL_LITERAL SSC_COMPOUND_LITERAL(Threegen, 0)

#define R_ SSC_RESTRICT
SSC_BEGIN_C_DECLS

static inline void
print_help(void)
{
  puts( 
    "Usage: 3gen [-h] [-l] [-u] [-d] [-s] [-a] [-f] [-E] Number_Characters\n"
    "Switches MUST be in seperate words. (i.e. 3gen -l -u 20; NOT 3gen -lu 20)\n"
    "-h, --help    : Print out this usage information to stdout.\n"
    "-l, --lower   : Use lowercase characters during password generation.\n"
    "-u, --upper   : Use uppercase characters during password generation.\n"
    "-d, --digit   : Use digit characters during password generation.\n"
    "-s, --symbol  : Use symbol characters during password generation.\n"
    "-a, --all     : Use all character sets during password generation.\n"
    "-f, --format  : Format the password output for easier readability.\n"
    "-E, --entropy : Supplement the RNG with a passphrase input from the keyboard."
  );
}

void
set_character_table(Threegen*);

void
threegen(int argc, char ** argv, Threegen* R_ ctx);

SSC_END_C_DECLS
#undef R_

#endif /* ~ THREEGEN_H */
