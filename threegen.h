#ifndef THREEGEN_H
#define THREEGEN_H
/* STD */
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
/* Shim */
#include <shim/macros.h>
#include <shim/operations.h>
#include <shim/args.h>
#include <shim/term.h>
/* Symm */
#include <symm/csprng.h>

#define THREEGEN_MAX_PW_SIZE		125
#define THREEGEN_PW_BUF_SIZE		(THREEGEN_MAX_PW_SIZE + 1)
#define THREEGEN_NUM_RAND_WORDS		THREEGEN_PW_BUF_SIZE
#define THREEGEN_NUM_RAND_BYTES		(THREEGEN_NUM_RAND_WORDS * 8)
/* These entropy bytes are going to Shim code with a hard-coded buffer size.
 * Use that hard-coded buffer size to determine the maximum number of bytes
 * we can take from stdin to supplement entropy.
 */
#define THREEGEN_MAX_ENT_SIZE		120
#define THREEGEN_ENT_BUF_SIZE		(THREEGEN_MAX_ENT_SIZE + 1 + SYMM_THREEFISH512_BLOCK_BYTES)
#define THREEGEN_NUM_LCASE		26
#define THREEGEN_NUM_UCASE		26
#define THREEGEN_NUM_DIGITS		10
#define THREEGEN_NUM_SYMBOLS		32
#define THREEGEN_NUM_ALL_CHARS		(THREEGEN_NUM_LCASE + THREEGEN_NUM_UCASE + THREEGEN_NUM_DIGITS + THREEGEN_NUM_SYMBOLS)
#define THREEGEN_UPPER_LIMIT		(UINT64_MAX - THREEGEN_NUM_ALL_CHARS)
#define THREEGEN_USE_LCASE		0b00000001
#define THREEGEN_USE_UCASE		0b00000010
#define THREEGEN_USE_DIGITS		0b00000100
#define THREEGEN_USE_SYMBOLS		0b00001000
#define THREEGEN_USE_FORMATTING		0b00010000
#define THREEGEN_GET_ENTROPY		0b00100000

typedef struct {
	uint8_t character_table [THREEGEN_NUM_ALL_CHARS];
	int     flags;
	int     requested_pw_size;
	int     num_chars;
} Threegen;

SHIM_BEGIN_DECLS

static inline void
print_help () {
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
set_character_table (Threegen *);

void
threegen (int, char **, Threegen * SHIM_RESTRICT);

SHIM_END_DECLS

#endif /* ~ THREEGEN_H */
