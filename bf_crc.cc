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



void bf_crc::print_settings(void)
{

	// Output Brute Force Settings
	std::cout << "Brute Force CRC Settings" << std::endl;
	std::cout << "------------------------" << std::endl;

	std::cout << "CRC Width		: " << crc_width_ << std::endl;

	std::cout << "Truncated Polynomial	";
	if (polynomial_ > 0)
		std::cout << ": 0x" << std::hex << polynomial_ << std::endl;
	else
		std::cout << ": 0x0 to 0x" << std::hex << MAX_VALUE(crc_width_) << std::endl;

	if (probe_initial_)
		std::cout << "Initial value		: 0x0 to 0x" << std::hex << MAX_VALUE(crc_width_) << std::endl;
	else
		std::cout << "Initial value		: " << std::hex << initial_ << std::endl;

	if (probe_final_xor_)
		std::cout << "Final xor		: 0x0 to 0x" << std::hex << MAX_VALUE(crc_width_) << std::endl;
	else
		std::cout << "final xor		: 0x" <<std::hex << final_xor_ << std::endl;

	std::cout << "Probe reflect in	: " << bool_to_str(probe_reflected_input_) << std::endl;
	std::cout << "{robe reflect out	: " << bool_to_str(probe_reflected_output_) << std::endl;
	std::cout << std::endl;	
}

bool bf_crc::brute_force(int thread_number, uint32_t search_poly_start, uint32_t search_poly_end, std::vector<test_vector_t> test_vectors) {

	// Verbose option only
	if (verbose_)
	{
		// Lock mutex to avoid garbled std_out
		mymutex.lock();

		// Thread information
		std::cout << "Thread " << thread_number << " started, searching polynomial " << std::hex << search_poly_start << " to " << std::hex << search_poly_end << std::endl;

		mymutex.unlock();
	}

	// Otherwise the returned list is going to take up a LOT of RAM
	assert(test_vectors.size() > 0);

	// Get a CRC checker
	crc_t crc(crc_width_);

	// Initial value defaults to 0
	uint32_t init = 0;

	// If init search is requested, set the search space
	uint32_t init_to_check = probe_initial_ ? MAX_VALUE(crc_width_) : 0;

	// Probe reflected input
	for(int probe_reflected_input = 0; 
		probe_reflected_input <= bool_to_int(probe_reflected_input_); 
			probe_reflected_input++) {

		// Probe reflected output
	    for(int probe_reflected_output = 0; 
			probe_reflected_output <= bool_to_int(probe_reflected_output_); 
				probe_reflected_output++) {

			// Check all possible polynomials
			for(uint32_t poly = search_poly_start; 
				poly <= search_poly_end && poly <= MAX_VALUE(crc_width_); 
					poly++) {

				// Probe all final xors
				for(uint32_t final_xor = (probe_final_xor_ ? 0 : final_xor_); 
					final_xor <= (probe_final_xor_ ? MAX_VALUE(crc_width_) : final_xor_); 
						final_xor++) {

					// Set the CRC engine settings (initial set to zero, igored)
					crc.set(poly, 0, final_xor, int_to_bool(probe_reflected_input), int_to_bool(probe_reflected_output));

					// For all possible initials
					for(init = 0; init <= init_to_check; init++) {

						// Start with true
						bool match = true;
						size_t m_i;

						// Over all test vectirs, test to see if CRC settings wor
						for(m_i = 0; match && (m_i < test_vectors.size()); m_i++)
							match = crc.calc_crc(init, test_vectors[m_i].message, test_vectors[m_i].crc);

						// If match is true there were no errors, TODO: why checl m_i against test_vectors_size?
						if(match == true && m_i == test_vectors.size()) {
							show_hit(poly, init, probe_reflected_input ? true : false, probe_reflected_output ? true : false);
						}

					} // end for loop, initials

					// Lock the mutex, blocks until mutex avaliable
					mymutex.lock();

					// Increase counter by initial's being checkeD 
					crc_counter += init_to_check;

					// TODO: is this a good way to do this?
					if(probe_final_xor_ || (poly % 0x80 == 0))
						print_stats();

					// Unlock the mutex
					mymutex.unlock();

				} // end for loop, final_xor

			} // end for loop, polynomial

		} // end for loop, reflected output

	} // end for loop, reflected input

	return false;
}

int bf_crc::do_brute_force(int num_threads, std::vector<test_vector_t> test_vectors){


	// Record start time for statistics
	gettimeofday(&start_time, NULL);
	gettimeofday(&current_time, NULL);

	// Start a thread pool
	ThreadPool<boost::function0<void> > pool;

	// Polystep is how the search polynomials are spread betweeen threads
	int poly_step = polynomial_ > 0 ? 1 : MAX_VALUE(crc_width_)/num_threads;

	if (verbose_)
	{
		std::cout << "Multithreaded CRC Brute Force Initiated" << std::endl;
		std::cout << "---------------------------------------" << std::endl;
		std::cout << "Number of threads	: " << std::dec << num_threads << std::endl;
		std::cout << "Number of test vectors	: " << std::dec << test_vectors.size() << std::endl;
		std::cout << std::endl;
	}

	// Step through search space, assigning a batch of polynomials to each thread 
	// (poly_step polynomials per thread)
	int thread_number = 0;
	for(uint32_t _poly = 0; _poly <= MAX_VALUE(crc_width_); _poly += poly_step + 1) {

		// Limit end poly size, rounding could cause problems with odd number of processors
		uint32_t end_poly = _poly + poly_step - 1;
		if (end_poly > MAX_VALUE(crc_width_)) end_poly = MAX_VALUE(crc_width_);

		// Start the thread
		pool.add(boost::bind(&bf_crc::brute_force, this, thread_number++, _poly, _poly + poly_step, test_vectors));

	}

	// Wait for all threads to complete
	pool.wait();

return 0;

}

