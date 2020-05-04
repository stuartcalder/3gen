/* Copyright (c) 2020 Stuart Steven Calder
 * See the accompanying LICENSE file for licensing information.
 */
#pragma once
#include <cstdlib>
#include <cstdio>
#include <limits>

#include <ssc/general/macros.hh>
#include <ssc/general/integers.hh>
#if 0
#	include <ssc/general/arg_mapping.hh>
#else
#	include <ssc/general/c_argument_map.hh>
#endif
#include <ssc/crypto/operations.hh>
#include <ssc/crypto/skein_csprng_f.hh>
#include <ssc/interface/terminal.hh>

using namespace ssc::ints;

class _PUBLIC Password_Generator
{
	public:
		static_assert (CHAR_BIT == 8);
		enum Int_Constants : int {
			Algorithm_Bits = 512,
			Algorithm_Bytes = Algorithm_Bits / CHAR_BIT,
			Max_Password_Length = 125,
			Password_Buffer_Bytes = Max_Password_Length + 1,
			Number_Random_Bytes = Password_Buffer_Bytes * sizeof(u64_t),
			Max_Entropy_Length = 120,
			Entropy_Buffer_Bytes = Max_Entropy_Length + 1 + Algorithm_Bytes,
			Number_Lowercase = 26,
			Number_Uppercase = Number_Lowercase,
			Number_Digits = 10,
			Number_Symbols = 32,
			Number_All_Characters = Number_Lowercase + Number_Uppercase + Number_Digits + Number_Symbols
		};
		_CTIME_CONST(u64_t) Upper_Limit = (std::numeric_limits<u64_t>::max)() - Number_All_Characters;

		using Skein_f     = ssc::Skein_F<Algorithm_Bits>;
		using CSPRNG_f    = ssc::Skein_CSPRNG_F<Algorithm_Bits>;
#if 0
		using Arg_Map_t   = ssc::Arg_Mapping::Arg_Map_t;
#endif

		Password_Generator () = delete;
		Password_Generator (ssc::C_Argument_Map &);
	private:
		u8_t character_table [Number_All_Characters];
		bool use_lowercase = false;
		bool use_uppercase = false;
		bool use_digits = false;
		bool use_symbols = false;
		bool use_formatting = false;
		bool supplement_entropy = false;
		int requested_password_size = 0;
		int number_characters = 0;
		char *temp_cstr = nullptr;

#if 0
		void process_arguments_ (Arg_Map_t &&);
#else
		void process_arguments_ (ssc::C_Argument_Map &);
#endif
		void print_help_ ();
		void set_character_table_ ();
		int generate_password_ (u8_t *password, u64_t const *random_words);
		void supplement_entropy_ (typename CSPRNG_f::Data *csprng_data, u8_t *buffer);
#if 0
		void process_pw_size_ (std::string &number);
#else
		void process_pw_size_ (char const *, int const);
#endif
};



