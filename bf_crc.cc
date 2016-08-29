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
    boost::format f("%1%B");
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

void bf_crc::show_hit(uint32_t poly, uint32_t init, bool ref_in, bool ref_out) {

  std::cout << std::endl
    << "----------------------[ MATCH ]--------------------------------\n"
    << "Found a model for the CRC calculation:\n"
    << "Truncated polynom : 0x" << std::hex << poly << " (" << std::dec << poly << ")\n"
    << "Initial value     : 0x" << std::hex << init << " (" << std::dec << init << ")\n"
    << "Final XOR         : 0x" << std::hex << final_xor_ << " (" << std::dec << final_xor_ << ")\n"
    << "Reflected input   : " << bool_to_str(ref_in) << "\n"
    << "Reflected output  : " << bool_to_str(ref_out) << "\n"
    //<< "Message offset    : from bit " << start_ << " .. " << end_ << " (end not included)\n"
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
		<< " done=" << (crc_counter*100.0/test_vector_count()) << "%"
		<< " (" << number_to_str(crc_counter) << " of " << number_to_str(test_vector_count()) << ")"
		<< " time_to_go=" <<  (test_vector_count() - crc_counter)/crcs_per_sec/3600 << " h"
		<< "     ";
    }
  }

}

bool bf_crc::brute_force(uint32_t search_poly_start, uint32_t search_poly_end, std::vector<test_vector_t> test_vectors) {
  
	// Get a CRC checker
	crc_t crc(crc_width_);
	uint32_t init = 0;
	uint32_t init_to_check = probe_initial_ ? MAX_VALUE(crc_width_) : 0;

	for(int probe_ref_in = 0; probe_ref_in <= bool_to_int(probe_reflected_input_); probe_ref_in++) {

	    for(int probe_ref_out = 0; probe_ref_out <= bool_to_int(probe_reflected_output_); probe_ref_out++) {

			for(uint32_t poly = search_poly_start; poly < search_poly_end && poly <= MAX_VALUE(crc_width_); poly++) {

				for(uint32_t final_xor = (probe_final_xor_ ? 0 : final_xor_); final_xor <= (probe_final_xor_ ? MAX_VALUE(crc_width_) : final_xor_); final_xor++) {

					crc.set(poly, 0, final_xor, int_to_bool(probe_ref_in), int_to_bool(probe_ref_out));

					for(init = 0; init <= init_to_check; init++) {

						bool match = true;
						size_t m_i;

						for(m_i = 0; match && (m_i < test_vectors.size()); m_i++) {

							match = crc.calc_crc(init, test_vectors[m_i].message, test_vectors[m_i].crc);

						}

						if(m_i == test_vectors.size()) {
							show_hit(poly, init, probe_ref_in ? true : false, probe_ref_out ? true : false);
						}

					}



					//boost::mutex::scoped_lock mylock(mymutex);
					mymutex.lock();
					crc_counter += init_to_check;

					if(probe_final_xor_ || (poly % 0x80 == 0))
						print_stats();
					mymutex.unlock();
				}
			}

		}

	}
	return false;
}

int bf_crc::do_brute_force(int num_threads, std::vector<test_vector_t> test_vectors){


	// For statistics
	gettimeofday(&start_time, NULL);
	gettimeofday(&current_time, NULL);

	ThreadPool<boost::function0<void> > pool;
	int poly_step = polynomial_ > 0 ? 1 : MAX_VALUE(crc_width_)/num_threads;


	// Step through search space, assigning a batch of polynomials to each thread 
	// (poly_step polynomials per thread)
	for(uint32_t _poly = 0; _poly <= MAX_VALUE(crc_width_); _poly += poly_step) {

		pool.add(boost::bind(&bf_crc::brute_force, this, _poly, _poly + poly_step, test_vectors));

	}

	pool.wait();

return 0;

}

