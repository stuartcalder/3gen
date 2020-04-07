/* Copyright (c) 2020 Stuart Steven Calder
 * See the accompanying LICENSE file for licensing information.
 */
#include "password_generator.hh"
#include <cstring>
#include <string>
#include <limits>
#include <ssc/general/arg_mapping.hh>
#include <ssc/general/parse_string.hh>
#include <ssc/memory/os_memory_locking.hh>
#include <ssc/crypto/implementation/common.hh>

#if    defined (LOCK_MEMORY) || defined (UNLOCK_MEMORY)
#	error 'LOCK_MEMORY or UNLOCK_MEMORY Already Defined'
#endif

#ifdef __SSC_MemoryLocking__
#	define   LOCK_MEMORY(memory,size)   ssc::lock_os_memory( memory, size )
#	define UNLOCK_MEMORY(memory,size) ssc::unlock_os_memory( memory, size )
#else
#	define   LOCK_MEMORY(memory,size)
#	define UNLOCK_MEMORY(memory,size)
#endif

Password_Generator::Password_Generator (int const argc, char const *argv[])
{
	// Process the command-line arguments.
	process_arguments_( ssc::Arg_Mapping{ argc, argv }.consume() );

	// Define the buffer size as the sum of all these required bytes.
	_CTIME_CONST(int) Buffer_Size = [](){
		int size = 0;
		size += Number_Random_Bytes;
		size += Threefish_t::Buffer_Bytes;
		size += UBI_t::Buffer_Bytes;
		size += CSPRNG_t::Buffer_Bytes;
		size += Entropy_Buffer_Bytes;
		size += Password_Buffer_Bytes;
		size += (size % sizeof(u64_t));
		return size;
	}();
	// Determine offsets of our sensitive data.
	_CTIME_CONST(int) Random_Bytes_Offset = 0;
	_CTIME_CONST(int) Threefish_Data_Offset = Random_Bytes_Offset + Number_Random_Bytes;
	_CTIME_CONST(int) UBI_Data_Offset = Threefish_Data_Offset + Threefish_t::Buffer_Bytes;
	_CTIME_CONST(int) CSPRNG_Data_Offset = UBI_Data_Offset + UBI_t::Buffer_Bytes;
	_CTIME_CONST(int) Entropy_Data_Offset = CSPRNG_Data_Offset + CSPRNG_t::Buffer_Bytes;
	_CTIME_CONST(int) Password_Offset = Entropy_Data_Offset + Entropy_Buffer_Bytes;

	// Create our buffer, aligned to 64-bit words.
	alignas(sizeof(u64_t)) u8_t buffer [Buffer_Size];

	// Lock memory from swapping on supported platforms.
	LOCK_MEMORY( buffer, sizeof(buffer) );

	// Create cryptographic objects.
	Threefish_t threefish{ reinterpret_cast<u64_t*>(buffer + Threefish_Data_Offset) };
	UBI_t ubi{ &threefish, (buffer + UBI_Data_Offset) };
	Skein_t skein{ &ubi };
	CSPRNG_t csprng{ &skein, (buffer + CSPRNG_Data_Offset) };
	// Fill the symbol table with the correct symbols according to what we got from the command-line arguments.
	set_character_table_();
	// Seed the RNG with additional entropy if specified to do so from the command-line arguments.
	if (supplement_entropy) {
		supplement_entropy_( csprng, skein, (buffer + Entropy_Data_Offset) );
	}
	// Generate enough randomness to produce the number of characters needed.
	{
		int random_bytes_left = Number_Random_Bytes;
		u8_t *ptr = buffer + Random_Bytes_Offset;
		_CTIME_CONST(int) Bytes = CSPRNG_t::Max_Bytes_Per_Call;
		while (random_bytes_left >= Bytes) {
			csprng.get( ptr, Bytes );
			ptr += Bytes;
			random_bytes_left -= Bytes;
		}
		if (random_bytes_left > 0)
			csprng.get( ptr, random_bytes_left );
	}
	// Process the generated randomness into a password using the generated character_table.
	int const size = generate_password_( reinterpret_cast<char*>(buffer + Password_Offset), reinterpret_cast<u64_t*>(buffer + Random_Bytes_Offset) );
	// Output the pseudorandomly generated password.
	if (use_formatting) {
		_CTIME_CONST(int) Chars_Per_Block = 5;
		_CTIME_CONST(int) Blocks_Per_Line = 5;

		int chars_left = size;
		int blocks_left = Blocks_Per_Line;
		char *pwd = reinterpret_cast<char*>(buffer + Password_Offset);
		while (chars_left >= Chars_Per_Block) {
			std::fwrite( pwd, sizeof(char), Chars_Per_Block, stdout );
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
			std::fwrite( pwd, sizeof(char), chars_left, stdout );
		}
		if (blocks_left != Blocks_Per_Line)
			std::putchar( '\n' );
	} else {
		std::fwrite( (buffer + Password_Offset), sizeof(char), size, stdout );
		std::putchar( '\n' );
	}
	
	ssc::zero_sensitive( buffer, sizeof(buffer) );
	UNLOCK_MEMORY( buffer, sizeof(buffer) );
} /* constructor */

void Password_Generator::process_arguments_ (Arg_Map_t &&arg_map)
{
	if (arg_map.size() < 2) {
		errx( "Error: No arguments. Use -h for help.\n" );
	}
	// Start counting at 1 to skip the executable name at arg_map[ 0 ].
	std::string number;
	for (size_t i = 1; i < arg_map.size(); ++i) {
		if (!arg_map[ i ].second.empty() && number.empty()) {
			number = std::move( arg_map[ i ].second );
		}
		if (arg_map[ i ].first == "-h" || arg_map[ i ].first == "--help") {
			print_help_();
			std::exit( EXIT_SUCCESS );
		} else if (arg_map[ i ].first == "-l" || arg_map[ i ].first == "--lower") {
			use_lowercase = true;
		} else if (arg_map[ i ].first == "-u" || arg_map[ i ].first == "--upper") {
			use_uppercase = true;
		} else if (arg_map[ i ].first == "-d" || arg_map[ i ].first == "--digit") {
			use_digits = true;
		} else if (arg_map[ i ].first == "-s" || arg_map[ i ].first == "--symbol") {
			use_symbols = true;
		} else if (arg_map[ i ].first == "-f" || arg_map[ i ].first == "--format") {
			use_formatting = true;
		} else if (arg_map[ i ].first == "-a" || arg_map[ i ].first == "--all") {
			use_lowercase = true;
			use_uppercase = true;
			use_digits = true;
			use_symbols = true;
		} else if (arg_map[ i ].first == "-E" || arg_map[ i ].first == "--entropy") {
			supplement_entropy = true;
		} else {
			if (!arg_map[ i ].first.empty() && number.empty()) {
				number = std::move( arg_map[ i ].first );
			}
			else if (!arg_map[ i ].second.empty() && number.empty()) {
				number = std::move( arg_map[ i ].second );
			}
		}
	}
	process_pw_size_( number );
} /* process_arguments_(Arg_Map_t&&) */
void Password_Generator::print_help_ ()
{
	_CTIME_CONST(auto) Help_String = "Usage: 3gen [-h] [-l] [-u] [-d] [-s] [-a] [-f] [-E] Number_Characters\n"
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
void Password_Generator::set_character_table_ ()
{
	// Establish relevant constants.
	_CTIME_CONST(char) Lowercase_Set[] = {
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
	};
	static_assert (sizeof(Lowercase_Set) == Number_Lowercase);
	_CTIME_CONST(char) Uppercase_Set[] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
	};
	static_assert (sizeof(Uppercase_Set) == Number_Uppercase);
	_CTIME_CONST(char) Digit_Set[] = {
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
	};
	static_assert (sizeof(Digit_Set) == Number_Digits);
	_CTIME_CONST(char) Symbol_Set[] = {
		'!', '"', '#', '$', '%', '&', '\'', '(', ')', '*',
		'+', ',', '-', '.', '/', ':', ';' , '<', '=', '>',
		'?', '@', '[','\\', ']', '^' , '_', '`', '{', '|',
		'}', '~'
	};
	static_assert (sizeof(Symbol_Set) == Number_Symbols);
	// Fill the character table with what characters we'll be using.
	char *character= character_table;
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
int Password_Generator::generate_password_ (char *password, u64_t const *random_words)
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
#if 0
		u64_t p;
		std::memcpy( &p, (random_words + i), sizeof(p) );
#endif
		u64_t p = random_words[ i ];
		if (p <= local_limit) {
			u64_t const p_prime = p - (p % quanta_per_character);
			offset = p_prime / quanta_per_character;
		} else {
			offset = number_characters - 1;
		}
		password[ i ] = character_table[ offset ];
	}
	return std::strlen( password );
} /* generate_password_() */
#if    defined (__UnixLike__)
#	define PROMPT "\n> "
#elif  defined (__Win64__)
#	define PROMPT "\n\r> "
#else
#	error 'Unsupported OS'
#endif
void Password_Generator::supplement_entropy_ (CSPRNG_t &csprng, Skein_t &skein, u8_t *buffer)
{
	static_assert (CHAR_BIT == 8);
	_CTIME_CONST(int) Hash_Size = Algorithm_Bytes;
	static_assert (Max_Entropy_Length == 120);
	_CTIME_CONST(auto) Entropy_Prompt = "Please input up to 120 random characters." PROMPT;
	static_assert (sizeof(char) == sizeof(u8_t));

	u8_t *hash = buffer;
	char *keyboard_input = reinterpret_cast<char*>(buffer + Hash_Size);
	int num_input_chars = ssc::obtain_password<Entropy_Buffer_Bytes>( keyboard_input, Entropy_Prompt );
	static_assert (Skein_t::State_Bytes == Hash_Size);
	skein.hash_native( hash, reinterpret_cast<u8_t*>(keyboard_input), num_input_chars );
	static_assert (CSPRNG_t::State_Bytes == Hash_Size);
	csprng.reseed( hash );
} /* supplement_entropy_(CSPRNG_t&,Skein_t&,u8_t*) */
void Password_Generator::process_pw_size_ (std::string &number)
{
	// Force it to be a number representing the requested password size.
	static_assert (Max_Password_Length == 125);
	_CTIME_CONST(int) Max_Chars = 3;
	if (number.size() > Max_Chars)
		errx( "Error: Maximum password size is 125 characters.\n" );
	else if (number.size() < 1)
		errx( "Error: Minimum password size is 1 character.\n" );
	if (ssc::enforce_integer( number )) {
		int length = atoi( number.c_str() );
		if (length >= 1 && length <= Max_Password_Length)
			requested_password_size = length;
		else {
			static_assert (Max_Password_Length == 125);
			errx( "Error: Minimum password size is 1 character; maximum password size is 125 characters.\n" );
		}
	} else {
		errx( "Error: Only integer inputs allowed for specifying maximum password size.\n" );
	}
} /* process_pw_size(std::string&) */
#undef PROMPT
#undef UNLOCK_MEMORY
#undef LOCK_MEMORY
