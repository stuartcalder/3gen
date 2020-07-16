/* Copyright (c) 2020 Stuart Steven Calder
 * See the accompanying LICENSE file for licensing information.
 */
#pragma once
#include <cstdlib>
#include <cstdio>
#include <limits>

#include <shim/macros.h>
#include <shim/operations.h>

#include <ssc/general/c_argument_map.hh>
#include <ssc/crypto/skein_csprng_f.hh>

using namespace ssc::ints;

class SHIM_PUBLIC
Password_Generator
{
	public:
		static_assert (CHAR_BIT == 8);
		enum Int_Constants : int {
			Algorithm_Bits = 512,
			Algorithm_Bytes = Algorithm_Bits / CHAR_BIT,
			Max_Password_Length = 125,
			Password_Buffer_Bytes = Max_Password_Length + 1,
			Number_Random_Bytes = Password_Buffer_Bytes * sizeof(uint64_t),
			Max_Entropy_Length = 120,
			Entropy_Buffer_Bytes = Max_Entropy_Length + 1 + Algorithm_Bytes,
			Number_Lowercase = 26,
			Number_Uppercase = Number_Lowercase,
			Number_Digits = 10,
			Number_Symbols = 32,
			Number_All_Characters = Number_Lowercase + Number_Uppercase + Number_Digits + Number_Symbols
		};
		static constexpr uint64_t Upper_Limit = (std::numeric_limits<uint64_t>::max)() - Number_All_Characters;

		using Skein_f     = ssc::Skein_F<Algorithm_Bits>;
		using CSPRNG_f    = ssc::Skein_CSPRNG_F<Algorithm_Bits>;

		Password_Generator () = delete;
		Password_Generator (ssc::C_Argument_Map &);
	private:
		uint8_t character_table [Number_All_Characters];
		bool use_lowercase = false;
		bool use_uppercase = false;
		bool use_digits = false;
		bool use_symbols = false;
		bool use_formatting = false;
		bool supplement_entropy = false;
		int requested_password_size = 0;
		int number_characters = 0;
		char *temp_cstr = nullptr;

		void
		process_arguments_ (ssc::C_Argument_Map &);

		void
		print_help_ ();

		void
		set_character_table_ ();

		int
		generate_password_ (uint8_t * SHIM_RESTRICT password, uint64_t const * SHIM_RESTRICT random_words);

		void
		supplement_entropy_ (typename CSPRNG_f::Data * SHIM_RESTRICT csprng_data, uint8_t * SHIM_RESTRICT buffer);

		void
		process_pw_size_ (char const * SHIM_RESTRICT, int const);
};



