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
#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <tr1/memory>
#include <boost/dynamic_bitset.hpp>
#include <boost/program_options.hpp>
#include <boost/foreach.hpp>
#include <boost/regex.hpp>
#include <boost/integer.hpp>
#include <boost/thread.hpp>
#include <boost/format.hpp>

#include "bf_crc.hpp"

#include "ThreadPool.h"

#define MAX_VALUE(width) (uint32_t)((1 << width) - 1)

namespace po = boost::program_options;

uint64_t crc_counter = 0;

int bf_crc::bool_to_int(bool v) { 
  return v ? 1 : 0; 
}

bool bf_crc::int_to_bool(int v) { 
  return v == 0 ? false : true; 
}

std::string bf_crc::bool_to_str(bool v) { 
  return v ? "true" : "false"; 
}

std::string bf_crc::number_to_str(uint64_t v) {
  if(v < 1000) {
    boost::format f("%1%");
    f % v;
    return f.str();
  }
  else if(v < 1000*1000) {
    boost::format f("%1%k");
    f % (v/1000);
    return f.str();
  }
  else if(v < 1000*1000*1000) {
    boost::format f("%1%M");
    f % (v/1000000);
    return f.str();
  }
  else if(v < 1000*1000*1000*1000L) {
    boost::format f("%1%G");
    f % (v/1000000000L);
    return f.str();
  }
  else {
    boost::format f("%1%T");
    f % (v/1000000000000);
    return f.str();
  }
  
}

uint64_t bf_crc::get_delta_time_in_ms(struct timeval const& start) {
  struct timeval end;
  gettimeofday(&end, NULL);  
  return (end.tv_sec*1000 + end.tv_usec/1000.0) - (start.tv_sec*1000 + start.tv_usec/1000.0); 
}

void bf_crc::show_hit(uint32_t poly, uint32_t init, struct bruteforce_params const& p, bool ref_in, bool ref_out) {
  std::cout << std::endl
    << "----------------------[ MATCH ]--------------------------------\n"
    << "Found a model for the CRC calculation:\n"
    << "Truncated polynom : 0x" << std::hex << poly << " (" << std::dec << poly << ")\n"
    << "Initial value     : 0x" << std::hex << init << " (" << std::dec << init << ")\n"
    << "Final XOR         : 0x" << std::hex << p._final_xor << " (" << std::dec << p._final_xor << ")\n"
    << "Reflected input   : " << bool_to_str(ref_in) << "\n"
    << "Reflected output  : " << bool_to_str(ref_out) << "\n"
    << "Message offset    : from bit " << p._start << " .. " << p._end << " (end not included)\n"
    << "\n";
}

void bf_crc::print_stats(void) {
  
  if(get_delta_time_in_ms(current_time) > 1000) {

    gettimeofday(&current_time, NULL);
    uint64_t elapsed_ms = get_delta_time_in_ms(start_time);

    if(elapsed_ms > 0) {
      uint64_t crcs_per_sec = (1000*crc_counter/elapsed_ms);
      std::cout << "\rtime=" << (elapsed_ms/1000) << "s "
		<< "CRCs/s=" <<  crcs_per_sec
		<< " done=" << (crc_counter*100.0/crc_steps) << "%"
		<< " (" << number_to_str(crc_counter) << " of " << number_to_str(crc_steps) << ")"
		<< " time_to_go=" <<  (crc_steps - crc_counter)/crcs_per_sec/3600 << " h"
		<< "     ";
    }
  }

}

bool bf_crc::brute_force(struct bruteforce_params p) {
  
	// Get a CRC checker
	crc_t crc(p._width);
	uint32_t init = 0;
	uint32_t init_to_check = p._probe_initial ? MAX_VALUE(p._width) : 0;

	for(int probe_ref_in = 0; probe_ref_in <= bool_to_int(p._probe_ref_in); probe_ref_in++) {

	    for(int probe_ref_out = 0; probe_ref_out <= bool_to_int(p._probe_ref_out); probe_ref_out++) {

			for(uint32_t poly = p._start_poly; poly < p._end_poly && poly <= MAX_VALUE(p._width); poly++) {

				for(uint32_t final_xor = (p._probe_final_xor ? 0 : p._final_xor); final_xor <= (p._probe_final_xor ? MAX_VALUE(p._width) : p._final_xor); final_xor++) {

					crc.set(poly, 0, final_xor, int_to_bool(probe_ref_in), int_to_bool(probe_ref_out));

					for(init = 0; init <= init_to_check; init++) {

						bool match = true;
						size_t m_i;

						for(m_i = 0; match && (m_i < p._msg_list.size()); m_i++) {

							match = crc.calc_crc(init, p._msg_list[m_i], p._start, p._end, p._expected_crcs[m_i]);

						}

						if(m_i == p._msg_list.size()) {
							show_hit(poly, init, p, probe_ref_in ? true : false, probe_ref_out ? true : false);
						}

					}



					//boost::mutex::scoped_lock mylock(mymutex);
					mymutex.lock();
					crc_counter += init_to_check;

					if(p._probe_final_xor || (poly % 0x80 == 0))
						print_stats();
					mymutex.unlock();
				}
			}

		}

	}
	return false;
}

int bf_crc::do_brute_force(	unsigned int width,
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
					bool ref_out){


	// For statistics
	gettimeofday(&start_time, NULL);
	gettimeofday(&current_time, NULL);

	ThreadPool<boost::function0<void> > pool;
	int poly_step = poly > 0 ? 1 : MAX_VALUE(width)/num_threads;


	// Step through search space, assigning a batch of polynomials to each thread 
	// (poly_step polynomials per thread)
	for(uint32_t _poly = start_poly; _poly <= end_poly; _poly += poly_step) {

		struct bruteforce_params p(	width, 
									_poly, 
									_poly + poly_step, 
									final_xor, 
									initial,
									start, 
									end,
									msg_list, 
									expected_crcs,
					   				probe_final_xor,
									probe_initial,
									ref_in,
									ref_out);

		pool.add(boost::bind(&bf_crc::brute_force, this, p));

	}

	pool.wait();

return 0;

}

