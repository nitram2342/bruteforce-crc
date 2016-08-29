/*
 * Brute-force a CRC.
 *
 * Original Author: Martin Schobert <schobert@sitsec.net>
 * Modified by MarytnP <git@disputedip.com>
 *
 *    Copyright Martin Schobert and MartynP 2012 - 2016.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 *
 */

#ifndef _BRUTEFORCE_CRC_LIB_HPP_
#define _BRUTEFORCE_CRC_LIB_HPP_

#include <list>
#include <sys/time.h>
#include <boost/thread.hpp>
#include "crc.hpp"

#define MAX_VALUE(width) (uint32_t)((1 << width) - 1)

class bf_crc {

	public:

		typedef boost::dynamic_bitset<> bitset_t;
		typedef std::vector<bitset_t> message_list_t;
		typedef std::vector<uint32_t> expected_crc_list_t;

		typedef my_crc_basic crc_t;

		bf_crc(	uint16_t crc_width, 
				uint32_t polynomial, 
				bool probe_final_xor, 
				uint32_t final_xor, 
				bool probe_initial, 
				uint32_t initial, 
				bool probe_reflected_input, 
				bool probe_reflected_output)
		{
			set_parameters(	crc_width, 
							polynomial, 
							probe_final_xor, 
							final_xor, 
							probe_initial, 
							initial, 
							probe_reflected_input, 
							probe_reflected_output);
		}

private: 
    uint16_t crc_width_; 
    uint32_t polynomial_; 
	bool probe_final_xor_;
	uint32_t final_xor_;
	bool probe_initial_;
	uint32_t initial_;
	bool probe_reflected_input_;
	bool probe_reflected_output_;

	uint64_t test_vector_count_;

public: 
	void set_crc_width(uint16_t var) { crc_width_ = var; update_test_vector_count(); }
	uint16_t crc_width() const { return crc_width_; }
	void set_polynomial(uint32_t var) { polynomial_ = var; update_test_vector_count(); }
	uint32_t polynomial() const { return polynomial_; }
	void set_probe_final_xor(bool var) { probe_final_xor_ = var; update_test_vector_count(); }
	bool probe_final_xor() const { return probe_final_xor_; }
	void set_final_xor(uint32_t var) { final_xor_ = var; }
	uint32_t final_xor() const { return final_xor_; }
	void set_probe_initial(bool var) { probe_initial_ = var; update_test_vector_count(); }
	bool probe_initial() const { return probe_initial_; }
	void set_initial(uint32_t var) { initial_ = var; }
	uint32_t initial() const { return initial_; }
	void set_probe_reflected_input(bool var) { probe_reflected_input_ = var; update_test_vector_count(); }
	bool probe_reflected_input() const { return probe_reflected_input_; }
	void set_probe_reflected_output(bool var) { probe_reflected_output_ = var; update_test_vector_count(); }
	bool probe_reflected_output() const { return probe_reflected_output_; }

	message_list_t msg_list_;
	expected_crc_list_t expected_crcs_;
	int start_;
	int end_;

	private:

		struct timeval start_time;
		struct timeval current_time;

		boost::mutex mymutex;

		uint64_t get_delta_time_in_ms(struct timeval const& start);
		void show_hit(uint32_t poly, uint32_t init, bool ref_in, bool ref_out);
		void print_stats(void);

		void update_test_vector_count()
		{
			test_vector_count_ = 0;

			if (polynomial_ > 0)
				test_vector_count_ = 1;
			else
				test_vector_count_ = 1+MAX_VALUE(crc_width_);

			if (probe_final_xor_)
				test_vector_count_ *= 1+MAX_VALUE(crc_width_);

			if (probe_initial_)
				test_vector_count_ *= 1+MAX_VALUE(crc_width_);

			if (probe_reflected_input_)
				test_vector_count_ *= 2;

			if (probe_reflected_output_)
				test_vector_count_ *= 2;
		}

	public: 

		uint64_t crc_steps;

		static int bool_to_int(bool v);
		static bool int_to_bool(int v);
		static std::string bool_to_str(bool v);
		static std::string number_to_str(uint64_t v);
	
		void set_parameters(	uint16_t crc_width, 
								uint32_t polynomial, 
								bool probe_final_xor, 
								uint32_t final_xor, 
								bool probe_initial, 
								uint32_t initial, 
								bool probe_reflected_input, 
								bool probe_reflected_output)
		{
			set_crc_width(crc_width);
			set_polynomial(polynomial);
			set_probe_final_xor(probe_final_xor);
			set_final_xor(final_xor);
			set_probe_initial(probe_initial);
			set_initial(initial);
			set_probe_reflected_input(probe_reflected_input);
			set_probe_reflected_output(probe_reflected_output);
		}
/*
			size_t _start, _end; // message offsets
			message_list_t const & _msg_list;
			std::vector<fast_int_t> const & _expected_crcs;
*/
		bool brute_force(uint32_t search_poly_start, uint32_t search_poly_end);
		int do_brute_force(int num_threads);

};

#endif
