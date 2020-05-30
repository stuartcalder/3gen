/* Copyright (c) 2020 Stuart Steven Calder
 * See the accompanying LICENSE file for licensing information.
 */
#include "password_generator.hh"
#include <cstring>
#include <string>
#include <limits>
#include <ssc/general/c_argument_map.hh>
#include <ssc/general/parse_string.hh>
#include <ssc/memory/os_memory_locking.hh>
#include <ssc/crypto/implementation/common.hh>
using namespace ssc;

#if    defined (LOCK_MEMORY) || defined (UNLOCK_MEMORY)
#	error 'LOCK_MEMORY or UNLOCK_MEMORY Already Defined'
#endif

#ifdef SSC_FEATURE_MEMORYLOCKING
#	define   LOCK_MEMORY(memory,size)   ssc::lock_os_memory( memory, size )
#	define UNLOCK_MEMORY(memory,size) ssc::unlock_os_memory( memory, size )
#else
#	define   LOCK_MEMORY(memory,size)
#	define UNLOCK_MEMORY(memory,size)
#endif

Password_Generator::Password_Generator (C_Argument_Map &c_arg_map)
{
	// Process the command-line arguments.

	static_assert (Number_Random_Bytes % sizeof(u64_t) == 0,
		       "The number of random bytes must be divisible into words.");
	static constexpr int Number_Random_Words = Number_Random_Bytes / sizeof(u64_t);
	struct {
		typename CSPRNG_f::Data csprng_data;
		u64_t                   random_bytes  [Number_Random_Words];
		u8_t                    entropy_bytes [Entropy_Buffer_Bytes];
		u8_t                    password      [Password_Buffer_Bytes];
	} crypto;
	LOCK_MEMORY (&crypto,sizeof(crypto));
	CSPRNG_f::initialize_seed( &crypto.csprng_data );

	process_arguments_( c_arg_map );
	// Fill the symbol table with the correct symbols according to what we got from the command-line arguments.
	set_character_table_();
	// Seed the RNG with additional entropy if specified to do so from the command-line arguments.
	if (supplement_entropy) {
		supplement_entropy_( &crypto.csprng_data, crypto.entropy_bytes );
	}
	// Generate enough randomness to produce the number of characters needed.
	{
	CSPRNG_f::get( &crypto.csprng_data,
		       reinterpret_cast<u8_t*>(crypto.random_bytes),
		       Number_Random_Bytes );
	}
	// Process the generated randomness into a password using the generated character_table.
	int const size = generate_password_ ( crypto.password, crypto.random_bytes );
	// Output the pseudorandomly generated password.
	if (use_formatting) {
		enum {
			Chars_Per_Block = 5,
			Blocks_Per_Line = 5
		};

		int chars_left = size;
		int blocks_left = Blocks_Per_Line;
		u8_t *pwd = crypto.password;
		while (chars_left >= Chars_Per_Block) {
			std::fwrite( pwd, sizeof(u8_t), Chars_Per_Block, stdout );
			pwd        += Chars_Per_Block;
			chars_left -= Chars_Per_Block;
			if (--blocks_left == 0) {
				blocks_left = Blocks_Per_Line;
				std::putchar( '\n' );
			} else {
				std::fputs( "  ", stdout );
			}
		}
		if (chars_left > 0) {
			std::fwrite( pwd, sizeof(u8_t), chars_left, stdout );
		}
		if (blocks_left != Blocks_Per_Line)
			std::putchar( '\n' );
	} else {
		std::fwrite( crypto.password, sizeof(u8_t), size, stdout );
		std::putchar( '\n' );
	}
	
	ssc::zero_sensitive( &crypto, sizeof(crypto) );
	UNLOCK_MEMORY (&crypto,sizeof(crypto));
} /* constructor */

void
Password_Generator::process_arguments_ (C_Argument_Map &c_arg_map)
{
	int const count = c_arg_map.count;
	if( count == 0 )
		errx( "Error: Called with no arguments.\n" );
	for( int i = 0; i < count; ++i ) {
		if( c_arg_map.c_strings[ i ] ) {
			if( c_arg_map.argument_cmp( i, "-h"    , (sizeof("-h")     - 1) ) ||
			    c_arg_map.argument_cmp( i, "--help", (sizeof("--help") - 1) ) )
			{
				c_arg_map.c_strings[ i ] = nullptr;
				print_help_();
				std::exit( EXIT_SUCCESS );
			} else
			if( c_arg_map.argument_cmp( i, "-l"     , (sizeof("-l")      - 1) ) ||
			    c_arg_map.argument_cmp( i, "--lower", (sizeof("--lower") - 1) ) )
			{
				c_arg_map.c_strings[ i ] = nullptr;
				use_lowercase = true;
			} else
			if( c_arg_map.argument_cmp( i, "-u"     , (sizeof("-u")      - 1) ) ||
			    c_arg_map.argument_cmp( i, "--upper", (sizeof("--upper") - 1) ) )
			{
				c_arg_map.c_strings[ i ] = nullptr;
				use_uppercase = true;
			} else
			if( c_arg_map.argument_cmp( i, "-d"     , (sizeof("-d")      - 1) ) ||
			    c_arg_map.argument_cmp( i, "--digit", (sizeof("--digit") - 1) ) )
			{
				c_arg_map.c_strings[ i ] = nullptr;
				use_digits = true;
			} else
			if( c_arg_map.argument_cmp( i, "-s"      , (sizeof("-s")       - 1) ) ||
			    c_arg_map.argument_cmp( i, "--symbol", (sizeof("--symbol") - 1) ) )
			{
				c_arg_map.c_strings[ i ] = nullptr;
				use_symbols = true;
			} else
			if( c_arg_map.argument_cmp( i, "-f"      , (sizeof("-f")       - 1) ) ||
			    c_arg_map.argument_cmp( i, "--format", (sizeof("--format") - 1) ) )
			{
				c_arg_map.c_strings[ i ] = nullptr;
				use_formatting = true;
			} else
			if( c_arg_map.argument_cmp( i, "-a"   , (sizeof("-a")    - 1) ) ||
			    c_arg_map.argument_cmp( i, "--all", (sizeof("--all") - 1) ) )
			{
				c_arg_map.c_strings[ i ] = nullptr;
				use_lowercase = true;
				use_uppercase = true;
				use_digits = true;
				use_symbols = true;
			} else
			if( c_arg_map.argument_cmp( i, "-E"       , (sizeof("-E")        - 1) ) ||
			    c_arg_map.argument_cmp( i, "--entropy", (sizeof("--entropy") - 1) ) )
			{
				c_arg_map.c_strings[ i ] = nullptr;
				supplement_entropy = true;
			} else {
				process_pw_size_( c_arg_map.c_strings[ i ], static_cast<int>(c_arg_map.sizes[ i ]) );
			}
		}
	}
}
void
Password_Generator::print_help_ ()
{
	static constexpr auto &Help_String = "Usage: 3gen [-h] [-l] [-u] [-d] [-s] [-a] [-f] [-E] Number_Characters\n"
		                             "Switches MUST be in seperate words. (i.e. 3gen -l -u 20; NOT 3gen -lu 20)\n"
					     "-h, --help    : Print out this usage information to stdout.\n"
					     "-l, --lower   : Use lowercase characters during password generation.\n"
					     "-u, --upper   : Use uppercase characters during password generation.\n"
					     "-d, --digit   : Use digit characters during password generation.\n"
					     "-s, --symbol  : Use symbol characters during password generation.\n"
					     "-a, --all     : Use all character sets during password generation.\n"
					     "-f, --format  : Format the password output for easier readability.\n"
					     "-E, --entropy : Supplement the RNG with a passphrase input from the keyboard.";
	std::puts( Help_String );
} /* print_help_() */
void
Password_Generator::set_character_table_ ()
{
	// Establish relevant constants.
	static constexpr u8_t Lowercase_Set[] = {
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
	};
	static_assert (sizeof(Lowercase_Set) == Number_Lowercase);
	static constexpr u8_t Uppercase_Set[] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
	};
	static_assert (sizeof(Uppercase_Set) == Number_Uppercase);
	static constexpr u8_t Digit_Set[] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
	};
	static_assert (sizeof(Digit_Set) == Number_Digits);
	static constexpr u8_t Symbol_Set[] = {
		'!', '"', '#', '$', '%', '&', '\'', '(', ')', '*',
		'+', ',', '-', '.', '/', ':', ';' , '<', '=', '>',
		'?', '@', '[','\\', ']', '^' , '_', '`', '{', '|',
		'}', '~'
	};
	static_assert (sizeof(Symbol_Set) == Number_Symbols);
	// Fill the character table with what characters we'll be using.
	u8_t *character= character_table;
	// Force at least one character set to be enabled by the end.
	bool one_is_valid = false;
	if (use_lowercase) {
		std::memcpy( character, Lowercase_Set, sizeof(Lowercase_Set) );
		character += sizeof(Lowercase_Set);
		number_characters += sizeof(Lowercase_Set);
		one_is_valid = true;
	}
	if (use_uppercase) {
		std::memcpy( character, Uppercase_Set, sizeof(Uppercase_Set) );
		character += sizeof(Uppercase_Set);
		number_characters += sizeof(Uppercase_Set);
		one_is_valid = true;
	}
	if (use_digits) {
		std::memcpy( character, Digit_Set, sizeof(Digit_Set) );
		character += sizeof(Digit_Set);
		number_characters += sizeof(Digit_Set);
		one_is_valid = true;
	}
	if (use_symbols) {
		std::memcpy( character, Symbol_Set, sizeof(Symbol_Set) );
		number_characters += sizeof(Symbol_Set);
		one_is_valid = true;
	}
	if (!one_is_valid)
		errx( "Error: No valid character sets chosen. Use -h for help.\n" );
} /* set_character_table_() */
int
Password_Generator::generate_password_ (u8_t *password, u64_t const *random_words)
{
	// Define the upper limit, local limit, and quanta per character.
	// 	* The upper limit marks the maximum.
	// 	* The local limit marks the maximum that is perfectly divisible by the number of characters
	// 	  in the character_table.
	// 	* The quanta per character describes the number of discrete integer values that map to
	// 	  a given character offset.
	// 	* (local_limit) == (number_characters * quanta_per_character)
	u64_t const local_limit = Upper_Limit + (Upper_Limit % static_cast<u64_t>(number_characters));
	u64_t const quanta_per_character = local_limit / static_cast<u64_t>(number_characters);

	std::memset( password, 0, Password_Buffer_Bytes );
	u64_t offset;
	for (int i = 0; i < requested_password_size; ++i) {
		u64_t p = random_words[ i ];
		if (p <= local_limit) {
			u64_t const p_prime = p - (p % quanta_per_character);
			offset = p_prime / quanta_per_character;
		} else {
			offset = number_characters - 1;
		}
		password[ i ] = character_table[ offset ];
	}
	return std::strlen( reinterpret_cast<char*>(password) );
} /* generate_password_() */
#if    defined (SSC_OS_UNIXLIKE)
#	define PROMPT "\n> "
#elif  defined (SSC_OS_WIN64)
#	define PROMPT "\n\r> "
#else
#	error 'Unsupported OS'
#endif
void
Password_Generator::supplement_entropy_ (typename CSPRNG_f::Data *csprng_data,
		                         u8_t                    *buffer)
{
	static_assert (CHAR_BIT == 8, "Bytes must be 8 bits.");
	static_assert (Max_Entropy_Length == 120);
	static constexpr int Hash_Size = Algorithm_Bytes;
	static constexpr auto &Entropy_Prompt = "Please input up to 120 random characters." PROMPT ;
	u8_t *hash = buffer;
	u8_t *keyboard_input = hash + Hash_Size;
	int num_input_chars = ssc::obtain_password<Entropy_Buffer_Bytes>( keyboard_input, Entropy_Prompt );
	Skein_f::hash_native( &(csprng_data->skein_data), hash, keyboard_input, num_input_chars );
	CSPRNG_f::reseed( csprng_data, hash );

} /* supplement_entropy_(CSPRNG_t&,Skein_t&,u8_t*) */
void
Password_Generator::process_pw_size_ (char const *number, int const size)
{
	if( size > 3 )
		errx( "Error: Maximum password size is 125 characters.\n" );
	else if( size < 1 )
		errx( "Error: Minimum password size is 1 character.\n" );
	if( temp_cstr != nullptr )
		errx( "Error: temp_cstr not already nullptr.\n" );
	temp_cstr = static_cast<char*>(std::malloc( size + 1 ));
	if( temp_cstr == nullptr )
		errx( Generic_Error::Alloc_Failure );
	{
		std::memcpy( temp_cstr, number, (size + 1) );
		int num_digits = shift_left_digits( temp_cstr, size );
		if( num_digits < 1 || num_digits > 3)
			errx( "Error: Minimum password size is 1 character; maximum password size is 125 characters.\n" );
		int size = std::atoi( temp_cstr );
		if( size >= 1 && size <= Max_Password_Length )
			requested_password_size = size;
		else {
			static_assert (Max_Password_Length == 125);
			errx( "Error: Minimum password size is 1 character; maximum password size is 125 characters.\n" );
		}
	}
	std::free( temp_cstr );
	temp_cstr = nullptr;
} /* process_pw_size(std::string&) */
#undef PROMPT
#undef UNLOCK_MEMORY
#undef LOCK_MEMORY
