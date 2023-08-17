#include "Threegen.h"
#include "CommandLineArg.h"
#include <SSC/Error.h>
#include <SSC/MemLock.h>

#define R_ SSC_RESTRICT

#ifdef SSC_MEMLOCK_H
  #define LOCK_INIT_              SSC_MemLock_Global_initHandled()
  #define  LOCK_M_(Ptr, Size)     SSC_MemLock_lockOrDie(Ptr, Size)
  #define ULOCK_M_(Ptr, Size)     SSC_MemLock_unlockOrDie(Ptr, Size)
  #define ALLOC_(Alignment, Size) SSC_alignedMallocOrDie(Alignment, Size)
  #define DEALLOC_(Ptr)           SSC_alignedFree(Ptr)
#else
  #define LOCK_INIT_ /* Nil. */
  #define LOCK_M_    /* Nil. */
  #define ULOCK_M_   /* Nil. */
  #define ALLOC_(Discard_, Size) SSC_mallocOrDie(Size)
  #define DEALLOC_(Ptr)          free(Ptr)
#endif

typedef struct {
  PPQ_CSPRNG csprng;
  uint64_t   rand_bytes [THREEGEN_NUM_RAND_WORDS];
  uint8_t    ent_bytes  [THREEGEN_ENT_BUF_SIZE];
  uint8_t    passwd     [THREEGEN_PW_BUF_SIZE];
} Crypto;
#define CRYPTO_NULL_LITERAL SSC_COMPOUND_LITERAL(Crypto, 0)

void set_character_table (Threegen* ctx)
{
  static const uint8_t Lowercase_Set[] = {
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
  };
  SSC_STATIC_ASSERT(sizeof(Lowercase_Set) == THREEGEN_NUM_LCASE, "Set size mismatch.");
  static const uint8_t Uppercase_Set[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
  };
  SSC_STATIC_ASSERT(sizeof(Uppercase_Set) == THREEGEN_NUM_UCASE, "Set size mismatch.");
  static const uint8_t Digit_Set[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
  };
  SSC_STATIC_ASSERT(sizeof(Digit_Set) == THREEGEN_NUM_DIGITS, "Set size mismatch.");
  static const uint8_t Symbol_Set[] = {
    '!', '"', '#', '$','%', '&', '\'', '(', ')', '*',
    '+', ',', '-', '.', '/', ':', ';', '<', '=', '>',
    '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|',
    '}', '~'
  };
  SSC_STATIC_ASSERT(sizeof(Symbol_Set) == THREEGEN_NUM_SYMBOLS, "Set size mismatch.");
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
  SSC_assertMsg(one_is_valid, "Error: No valid character sets chosen. Use -h for help.\n");
}

#if defined(SSC_OS_UNIXLIKE)
 #define PROMPT_ "\n> "
#elif defined(SSC_OS_WINDOWS)
 #define PROMPT_ "\n\r> "
#else
 #error "Unsupported OS."
#endif

#define ENT_PROMPT_ "Please input up to " SSC_STRINGIFY(THREEGEN_MAX_ENT_SIZE) " random characters." PROMPT_

static void
supplement_entropy_(PPQ_CSPRNG* R_ csprng, uint8_t* R_ buffer)
{
  uint8_t* hash = buffer;
  uint8_t* keyboard_input = hash + PPQ_THREEFISH512_BLOCK_BYTES;
  SSC_Terminal_init();
  int num_input_chars = SSC_Terminal_getPassword(keyboard_input,
    ENT_PROMPT_,
    1,
    THREEGEN_MAX_ENT_SIZE,
    (THREEGEN_MAX_ENT_SIZE + 1));
  SSC_Terminal_end();
  PPQ_Skein512_hashNative(&csprng->ubi512,
    hash,
    keyboard_input,
    num_input_chars);
  PPQ_CSPRNG_reseed(csprng, hash);
}

static size_t
generate_password_(
 Threegen* R_       ctx,
 uint8_t* R_        pw,
 const uint64_t* R_ rand_words)
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
    }
    else
      offset = ctx->num_chars - 1;
    pw[i] = ctx->character_table[offset];
  }
  return strlen((char*)pw);
}

static const SSC_ArgLong longs[] = {
  SSC_ARGLONG_LITERAL(all_argproc, "all"),
  SSC_ARGLONG_LITERAL(digit_argproc, "digit"),
  SSC_ARGLONG_LITERAL(entropy_argproc, "entropy"),
  SSC_ARGLONG_LITERAL(format_argproc, "format"),
  SSC_ARGLONG_LITERAL(help_argproc, "help"),
  SSC_ARGLONG_LITERAL(lower_argproc, "lower"),
  SSC_ARGLONG_LITERAL(symbol_argproc, "symbol"),
  SSC_ARGLONG_LITERAL(upper_argproc, "upper"),
  SSC_ARGLONG_NULL_LITERAL
};
#define N_LONGS_ ((sizeof(longs) / sizeof(SSC_ArgLong)) - 1)
static const SSC_ArgShort shorts[] = {
  SSC_ARGSHORT_LITERAL(entropy_argproc, 'E'),
  SSC_ARGSHORT_LITERAL(all_argproc, 'a'),
  SSC_ARGSHORT_LITERAL(digit_argproc, 'd'),
  SSC_ARGSHORT_LITERAL(format_argproc, 'f'),
  SSC_ARGSHORT_LITERAL(help_argproc, 'h'),
  SSC_ARGSHORT_LITERAL(lower_argproc, 'l'),
  SSC_ARGSHORT_LITERAL(symbol_argproc, 's'),
  SSC_ARGSHORT_LITERAL(upper_argproc, 'u'),
  SSC_ARGSHORT_NULL_LITERAL
};
#define N_SHORTS_ ((sizeof(shorts) / sizeof(SSC_ArgShort)) - 1)

void threegen (int argc, char** argv, Threegen* R_ ctx)
{
  LOCK_INIT_;
  Crypto* crypto;
  SSC_assertMsg(SSC_NULL != (crypto = (Crypto*)ALLOC_(SSC_MemLock_Global.page_size, sizeof(Crypto))),
  "Error: Memory allocation failure!\n");
  LOCK_M_(crypto, sizeof(crypto));
  PPQ_CSPRNG_init(&crypto->csprng);
  SSC_assert(argc);
  SSC_processCommandLineArgs(argc - 1, argv + 1, N_SHORTS_, shorts, N_LONGS_, longs, ctx, password_size_argproc);
  set_character_table(ctx);
  if (ctx->flags & THREEGEN_GET_ENTROPY)
    supplement_entropy_(&crypto->csprng, crypto->ent_bytes);
  SSC_OPENBSD_PLEDGE("stdio tty", SSC_NULL);
  PPQ_CSPRNG_get(&crypto->csprng, (uint8_t*)crypto->rand_bytes, sizeof(crypto->rand_bytes));
  const int size = generate_password_(ctx, crypto->passwd, crypto->rand_bytes);
  if (ctx->flags & THREEGEN_USE_FORMATTING) {
    enum {
      CHARS_PER_BLOCK_ = 5,
      BLOCKS_PER_LINE_ = 5
    };
    int chars_left = size;
    int blocks_left = BLOCKS_PER_LINE_;
    uint8_t* pw = crypto->passwd;
    while (chars_left >= CHARS_PER_BLOCK_) {
      fwrite(pw, 1, CHARS_PER_BLOCK_, stdout);
      pw         += CHARS_PER_BLOCK_;
      chars_left -= CHARS_PER_BLOCK_;
      if (!(--blocks_left)) {
        blocks_left = BLOCKS_PER_LINE_;
        putchar('\n');
      }
      else
        fputs("  ", stdout);
    }
    if (chars_left)
      fwrite(pw, 1, chars_left, stdout);
    if (blocks_left != BLOCKS_PER_LINE_)
      putchar('\n');
  }
  else {
    fwrite(crypto->passwd, 1, size, stdout);
    putchar('\n');
  }
  SSC_secureZero(crypto, sizeof(*crypto));
  ULOCK_M_(crypto, sizeof(crypto));
  DEALLOC_(crypto);
  SSC_secureZero(ctx, sizeof(*ctx));
}
