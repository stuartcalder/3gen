#include "threegen.h"
#include "args.h"
#include <Base/errors.h>
#include <Base/mlock.h>

#define R_(p) p BASE_RESTRICT

#ifdef BASE_MLOCK_H
#  define LOCK_INIT_ do { \
	Base_MLock_g_init_handled(); \
} while (0)
#  define  LOCK_M_(mem_ptr, size)   Base_mlock(mem_ptr, size)
#  define ULOCK_M_(mem_ptr, size) Base_munlock(mem_ptr, size)
#else
#  define LOCK_INIT_ /* Nil. */
#  define LOCK_M_    /* Nil. */
#  define ULOCK_M_   /* Nil. */
#endif

typedef struct {
	Skc_CSPRNG csprng;
	uint64_t   rand_bytes [THREEGEN_NUM_RAND_WORDS];
	uint8_t    ent_bytes  [THREEGEN_ENT_BUF_SIZE];
	uint8_t    passwd     [THREEGEN_PW_BUF_SIZE];
} Crypto;

void set_character_table (Threegen* ctx) {
	static uint8_t const Lowercase_Set[] = {
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
		'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
	};
	BASE_STATIC_ASSERT(sizeof(Lowercase_Set) == THREEGEN_NUM_LCASE, "Set size mismatch.");
	static uint8_t const Uppercase_Set[] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
		'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
	};
	BASE_STATIC_ASSERT(sizeof(Uppercase_Set) == THREEGEN_NUM_UCASE, "Set size mismatch.");
	static uint8_t const Digit_Set[] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
	};
	BASE_STATIC_ASSERT(sizeof(Digit_Set) == THREEGEN_NUM_DIGITS, "Set size mismatch.");
	static uint8_t const Symbol_Set[] = {
		'!', '"', '#', '$','%', '&', '\'', '(', ')', '*',
		'+', ',', '-', '.', '/', ':', ';', '<', '=', '>',
		'?', '@', '[', '\\', ']', '^', '_', '`', '{', '|',
		'}', '~'
	};
	BASE_STATIC_ASSERT(sizeof(Symbol_Set) == THREEGEN_NUM_SYMBOLS, "Set size mismatch.");
	uint8_t* character = ctx->character_table;
	bool one_is_valid = false;
	if (ctx->flags & THREEGEN_USE_LCASE) {
		memcpy(character, Lowercase_Set, sizeof(Lowercase_Set));
		character += sizeof(Lowercase_Set);
		ctx->num_chars += sizeof(Lowercase_Set);
		one_is_valid = true;
	}
	if (ctx->flags & THREEGEN_USE_UCASE) {
		memcpy(character, Uppercase_Set, sizeof(Uppercase_Set));
		character += sizeof(Uppercase_Set);
		ctx->num_chars += sizeof(Uppercase_Set);
		one_is_valid = true;
	}
	if (ctx->flags & THREEGEN_USE_DIGITS) {
		memcpy(character, Digit_Set, sizeof(Digit_Set));
		character += sizeof(Digit_Set);
		ctx->num_chars += sizeof(Digit_Set);
		one_is_valid = true;
	}
	if (ctx->flags & THREEGEN_USE_SYMBOLS) {
		memcpy(character, Symbol_Set, sizeof(Symbol_Set));
		character += sizeof(Symbol_Set);
		ctx->num_chars += sizeof(Symbol_Set);
		one_is_valid = true;
	}
	Base_assert_msg(one_is_valid, "Error: No valid character sets chosen. Use -h for help.\n");
}

#if    defined (BASE_OS_UNIXLIKE)
#	define PROMPT_ "\n> "
#elif  defined (BASE_OS_WINDOWS)
#	define PROMPT_ "\n\r> "
#else
#	error "Unsupported OS."
#endif

#define ENT_PROMPT_ "Please input up to " BASE_STRINGIFY(THREEGEN_MAX_ENT_SIZE) " random characters." PROMPT_

static void supplement_entropy_ (R_(Skc_CSPRNG*) csprng, R_(uint8_t*) buffer) {
	uint8_t* hash = buffer;
	uint8_t* keyboard_input = hash + SKC_THREEFISH512_BLOCK_BYTES;
	Base_term_init();
	int num_input_chars = Base_term_obtain_password(keyboard_input,
							ENT_PROMPT_,
							1,
							THREEGEN_MAX_ENT_SIZE,
							(THREEGEN_MAX_ENT_SIZE + 1));
	Base_term_end();
	Skc_Skein512_hash_native(&csprng->ubi512,
				 hash,
				 keyboard_input,
				 num_input_chars);
	Skc_CSPRNG_reseed(csprng, hash);
}

static size_t generate_password_ (R_(Threegen*)       ctx,
				  R_(uint8_t*)        pw,
				  R_(const uint64_t*) rand_words)
{
	const uint64_t local_limit = THREEGEN_UPPER_LIMIT - (THREEGEN_UPPER_LIMIT % ((uint64_t)ctx->num_chars));
	const uint64_t quanta_per_char = local_limit / ((uint64_t)ctx->num_chars); /* The number of integers per each character. */
	memset(pw, 0, THREEGEN_PW_BUF_SIZE);
	const int requested_pw_size = ctx->requested_pw_size;
	for (int i = 0; i < requested_pw_size; ++i) {
		uint64_t offset;
		uint64_t p = rand_words[i];
		if (p <= local_limit) {
			uint64_t const p_prime = p - (p % quanta_per_char);
			offset = p_prime / quanta_per_char;
		} else {
			offset = ctx->num_chars - 1;
		}
		pw[i] = ctx->character_table[offset];
	}
	return strlen((char*)pw);
}

void threegen (int argc, char** argv, R_(Threegen*) ctx) {
	Crypto crypto;
	Skc_CSPRNG_init(&crypto.csprng);
	Base_process_args(argc, argv, arg_processor, ctx);
	set_character_table(ctx);
	if (ctx->flags & THREEGEN_GET_ENTROPY)
		supplement_entropy_(&crypto.csprng, crypto.ent_bytes);
	BASE_OPENBSD_PLEDGE ("stdio tty", NULL);
	Skc_CSPRNG_get(&crypto.csprng, (uint8_t*)crypto.rand_bytes, sizeof(crypto.rand_bytes));
	const int size = generate_password_(ctx, crypto.passwd, crypto.rand_bytes);
	if (ctx->flags & THREEGEN_USE_FORMATTING) {
		enum {
			CHARS_PER_BLOCK_ = 5,
			BLOCKS_PER_LINE_ = 5
		};
		int chars_left = size;
		int blocks_left = BLOCKS_PER_LINE_;
		uint8_t* pw = crypto.passwd;
		while (chars_left >= CHARS_PER_BLOCK_) {
			fwrite(pw, 1, CHARS_PER_BLOCK_, stdout);
			pw         += CHARS_PER_BLOCK_;
			chars_left -= CHARS_PER_BLOCK_;
			if (!(--blocks_left)) {
				blocks_left = BLOCKS_PER_LINE_;
				putchar('\n');
			} else {
				fputs("  ", stdout);
			}
		}
		if (chars_left)
			fwrite(pw, 1, chars_left, stdout);
		if (blocks_left != BLOCKS_PER_LINE_)
			putchar('\n');
	} else {
		fwrite(crypto.passwd, 1, size, stdout);
		putchar('\n');
	}
	Base_secure_zero(&crypto, sizeof(crypto));
	Base_secure_zero(ctx, sizeof(*ctx));
}
