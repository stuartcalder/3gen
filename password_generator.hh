/* Copyright (c) 2020 Stuart Steven Calder
 * See the accompanying LICENSE file for licensing information.
 */
#pragma once
#include <cstdlib>
#include <cstdio>

#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#include <ssc/general/arg_mapping.hh>
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/threefish.hh>
#include <ssc/crypto/skein.hh>
#include <ssc/crypto/skein_csprng.hh>
#include <ssc/interface/terminal.hh>

using namespace ssc::ints;

class _PUBLIC Password_Generator
{
	public:
		static_assert (CHAR_BIT == 8);
		// Use our 512-bit suite of algorithms.
		_CTIME_CONST(int) Algorithm_Bits = 512;
		_CTIME_CONST(int) Algorithm_Bytes = Algorithm_Bits / CHAR_BIT;
		// Only allow generating passwords up to this size.
		_CTIME_CONST(int) Max_Password_Length = 120;
		_CTIME_CONST(int) Password_Buffer_Bytes = Max_Password_Length + 1;
		// A 64-bit word of random data to be mapped to each output character of password.
		_CTIME_CONST(int) Number_Random_Bytes = Password_Buffer_Bytes * sizeof(u64_t);
		// Only allow entropy inputs up to this size.
		_CTIME_CONST(int) Max_Entropy_Length = 120;
		_CTIME_CONST(int) Entropy_Buffer_Bytes = Max_Entropy_Length + 1 + Algorithm_Bytes;
		// There are 26 lowercase characters available.
		_CTIME_CONST(int) Number_Lowercase = 26;
		// There are 26 uppercase characters available.
		_CTIME_CONST(int) Number_Uppercase = 26;
		// There are 10 digit characters available.
		_CTIME_CONST(int) Number_Digits = 10;
		// There are 33 special symbols available.
		_CTIME_CONST(int) Number_Symbols = 32;
		_CTIME_CONST(int) Number_All_Characters = Number_Lowercase + Number_Uppercase + Number_Digits + Number_Symbols;

		_CTIME_CONST(u64_t) Upper_Limit = std::numeric_limits<u64_t>::max() - (Number_All_Characters + 1);

		// The specific algorithms to use.
		using Threefish_t = ssc::Threefish<Algorithm_Bits>;
		using UBI_t       = ssc::Unique_Block_Iteration<Threefish_t,Algorithm_Bits>;
		using Skein_t     = ssc::Skein<Algorithm_Bits>;
		using CSPRNG_t    = ssc::Skein_CSPRNG<Algorithm_Bits>;
		using Arg_Map_t   = ssc::Arg_Mapping::Arg_Map_t;

		Password_Generator () = delete;
		Password_Generator (int const argc, char const *argv[]);
	private:
		bool use_lowercase = false;
		bool use_uppercase = false;
		bool use_digits = false;
		bool use_symbols = false;
		bool use_formatting = false;
		bool supplement_entropy = false;
		int requested_password_size = 0;
		int number_characters = 0;
		char character_table [Number_All_Characters];

		void process_arguments_ (Arg_Map_t &&);
		void print_help_ ();
		void set_character_table_ ();
		int generate_password_ (char *password, u64_t const *random_words);
		void supplement_entropy_ (CSPRNG_t &csprng, Skein_t &skein, u8_t *buffer);
		void process_pw_size_ (std::string &number);
};



