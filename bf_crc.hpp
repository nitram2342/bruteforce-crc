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

class bf_crc {

	public:
		typedef uint32_t fast_int_t;
		typedef boost::dynamic_bitset<> bitset_t;
		typedef std::vector<bitset_t> message_list_t;
		typedef my_crc_basic crc_t;

	private:

		struct bruteforce_params {
			unsigned int _width;
			uint32_t _start_poly, _end_poly;
			uint32_t _final_xor;
			uint32_t _initial;
			size_t _start, _end; // message offsets
			message_list_t const & _msg_list;
			std::vector<fast_int_t> const & _expected_crcs;
			bool _probe_final_xor;
			bool _probe_initial;
			bool _probe_ref_in;
			bool _probe_ref_out;

			bruteforce_params(unsigned int width,
			uint32_t start_poly, 
			uint32_t end_poly,
			uint32_t final_xor,
			uint32_t initial,
			size_t start, 
			size_t end,
			message_list_t const & msg_list,
			std::vector<fast_int_t> const & expected_crcs,
			bool probe_final_xor,
			bool probe_initial,
			bool probe_ref_in,
			bool probe_ref_out) 
				: 	_width(width),
					_start_poly(start_poly),
					_end_poly(end_poly),
					_final_xor(final_xor),
					_initial(initial),
					_start(start),
					_end(end),
					_msg_list(msg_list),
					_expected_crcs(expected_crcs),
					_probe_final_xor(probe_final_xor),
					_probe_initial(probe_initial),
					_probe_ref_in(probe_ref_in),
					_probe_ref_out(probe_ref_out) {}

		}; // End struct bruteforce_params

	private:
		struct timeval start_time;
		struct timeval current_time;

		boost::mutex mymutex;

		uint64_t get_delta_time_in_ms(struct timeval const& start);
		void show_hit(uint32_t poly, uint32_t init, struct bruteforce_params const& p, bool ref_in, bool ref_out);
		void print_stats(void);

	public: 

		uint64_t crc_steps;

		int bool_to_int(bool v);
		bool int_to_bool(int v);
		std::string bool_to_str(bool v);
		std::string number_to_str(uint64_t v);

		bool brute_force(struct bruteforce_params p);
		int do_brute_force(	unsigned int width,
							fast_int_t poly,
							fast_int_t start_poly,
							fast_int_t end_poly,
							int num_threads,
							uint32_t final_xor,
							uint32_t initial,
							size_t start,
							size_t end,
							message_list_t msg_list,
							std::vector<fast_int_t>expected_crcs,
							bool probe_final_xor,
							bool probe_initial,
							bool ref_in,
							bool ref_out);

};

#endif
