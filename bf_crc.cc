/*
 * Brute-force CRC based on known good vectors
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

boost::dynamic_bitset<> bf_crc::convert_uint8_to_bitset(const uint8_t array[], size_t size) {

	boost::dynamic_bitset<> retVal(size*8);

	for (unsigned int i = 0; i < size; i++)
		for (int j = 0; j < 8; j++)
			retVal[i*8+j] = (array[i] >> (7-j)) & 0x1 ? true : false;

	return retVal;
}

boost::dynamic_bitset<> bf_crc::convert_string_to_bitset(std::string str)
{
	boost::dynamic_bitset<> retVal(str.length());

	for (size_t i = 0; i < str.length(); i++)
		retVal[i] = str[i] == '1' ? true : false;

	return retVal;
}

uint64_t bf_crc::get_delta_time_in_ms(struct timeval const& start) {
  struct timeval end;
  gettimeofday(&end, NULL);  
  return (end.tv_sec*1000 + end.tv_usec/1000.0) - (start.tv_sec*1000 + start.tv_usec/1000.0); 
}

void bf_crc::show_hit(crc_model_t model) {

  std::cout 
    << "----------------------------[ MATCH ]--------------------------------\n"
    << "Found a model for the CRC calculation:\n"
    << "Truncated polynom : 0x" << std::hex << model.polynomial << " (" << std::dec << model.polynomial << ")\n"
    << "Initial value     : 0x" << std::hex << model.initial << " (" << std::dec << model.initial << ")\n"
    << "Final XOR         : 0x" << std::hex << model.final_xor << " (" << std::dec << model.final_xor << ")\n"
    << "Reflected input   : " << bool_to_str(model.reflected_input) << "\n"
    << "Reflected output  : " << bool_to_str(model.reflected_output) << "\n"
    << std::endl << std::flush;

}

void bf_crc::print_stats(void) {
  
  if(get_delta_time_in_ms(current_time) > 1000) {

    gettimeofday(&current_time, NULL);
    uint64_t elapsed_ms = get_delta_time_in_ms(start_time);

    if(elapsed_ms > 0) {
      uint64_t crcs_per_sec = (1000*crc_counter/elapsed_ms);

      std::cout << "\rtime=" << (elapsed_ms/1000) << "s "
		<< "CRCs/s=" <<  crcs_per_sec;

	if (crcs_per_sec > 0)
{
	std::cout << " done=" << (crc_counter*100.0/test_vector_count()) << "%"
		<< " (" << number_to_str(crc_counter) << " of " << number_to_str(test_vector_count()) << ")"
		<< " time_to_go=" <<  (test_vector_count() - crc_counter)/crcs_per_sec/3600 << " h";
}

		std::cout << "     \r" << std::flush;
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
		std::cout << ": 0x" << std::hex << polynomial_ << std::dec << std::endl;
	else
		std::cout << ": 0x0 to 0x" << std::hex << max_value(crc_width_) << std::dec << std::endl;

	if (probe_initial_)
		std::cout << "Initial value		: 0x0 to 0x" << std::hex << max_value(crc_width_) << std::dec << std::endl;
	else
		std::cout << "Initial value		: 0x" << std::hex << initial_ << std::dec << std::endl;

	if (probe_final_xor_)
		std::cout << "Final xor		: 0x0 to 0x" << std::hex << max_value(crc_width_) << std::dec << std::endl;
	else
		std::cout << "final xor		: 0x" <<std::hex << final_xor_ << std::dec << std::endl;

	std::cout << "Probe reflect in	: " << bool_to_str(probe_reflected_input_) << std::endl;
	std::cout << "Probe reflect out	: " << bool_to_str(probe_reflected_output_) << std::endl;
	std::cout << "Permutation count	: " << test_vector_count_ << std::endl;
	std::cout << std::endl << std::flush;	
}

bool bf_crc::brute_force(int thread_number, uint32_t search_poly_start, uint32_t search_poly_end, std::vector<test_vector_t> test_vectors) {

	// Otherwise the returned list is going to take up a LOT of RAM
	assert(test_vectors.size() > 0);

	crc_t crc(crc_width_);

	// Initial value defaults to 0
	uint32_t init = 0;

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
				poly <= search_poly_end; 
					poly++) {

				// Probe all final xors
				for(uint32_t final_xor = (probe_final_xor_ ? 0 : final_xor_); 
					final_xor <= (probe_final_xor_ ? max_value(crc_width_) : final_xor_); 
						final_xor++) {

					// Set the CRC engine settings (initial set to zero, igored)
					crc.set(poly, 0, final_xor, int_to_bool(probe_reflected_input), int_to_bool(probe_reflected_output));

					// For all possible initials
					for(init = (probe_initial_ ? 0 : initial_); 
						init <= (probe_initial_ ? max_value(crc_width_) : initial_); 
							init++) {

						// Start with true
						bool match = true;
						size_t m_i;

						// Over all test vectirs, test to see if CRC settings work
						for(m_i = 0; match && (m_i < test_vectors.size()); m_i++)
							match = crc.calc_crc(init, test_vectors[m_i].message, test_vectors[m_i].crc);

						// If match is true there were no errors
						if(match == true && m_i == test_vectors.size()) {

							mymutex.lock();

							crc_model_t match = { poly, init, final_xor, int_to_bool(probe_reflected_input), int_to_bool(probe_reflected_output) };
							crc_model_match_.push_back(match);

							if (verbose_)	
								show_hit(match);

							print_stats();

							mymutex.unlock();
						}

						if (init == max_value(sizeof(init) * 8)) break;

					} // end for loop, initials

					mymutex.lock();

					crc_counter += probe_initial_ ? max_value(crc_width_) : 1;

					// TODO: is this a good way to do this?
					if(probe_final_xor_ || (crc_counter % 0x80000 == 0))
					{
						print_stats();
						//std::cout << std::endl << std::hex << poly << std::dec << "\r";
					}

					mymutex.unlock();

					// Handle overflow of for loop
					if (final_xor == max_value(sizeof(final_xor) * 8)) break;

				} // end for loop, final_xor

				if (poly == max_value(sizeof(poly) * 8)) break;

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

	if (verbose_)
	{
		// Show the current settings
		print_settings();

		// And this specific run's settings
		std::cout << std::endl;
		std::cout << "Multithreaded CRC Brute Force Initiated" << std::endl;
		std::cout << "---------------------------------------" << std::endl;
		std::cout << "Number of threads	: " << std::dec << num_threads << std::endl;
		std::cout << "Number of test vectors	: " << std::dec << test_vectors.size() << std::endl;
		std::cout << std::endl << std::flush;
	}

	// TODO: If you know the poly...
	if (polynomial_ > 0) {
		num_threads = 1;
	}

	// Clear the result store
	crc_model_match_.clear();

	// TODO: Search all known CRC combinations first

	// Step through search space, assigning a batch of polynomials to each thread 
	// (poly_step polynomials per thread)
	int thread_number = 0;
	
	// Polystep is how the search polynomials are spread betweeen threads
	int poly_step = polynomial_ > 0 ? 1 : max_value(crc_width_)/num_threads;

	// Handle low polynomial count
	if (poly_step == 0) poly_step = 1;

	for(int thread_number = 0; thread_number < num_threads; thread_number++) {

		uint32_t search_end = polynomial_ > 0 ? polynomial_ : (thread_number + 1) * poly_step - 1;

		// Due to math the last caluclate will wrap to zero?
		if (thread_number == num_threads-1 && polynomial_ == 0)
			search_end = max_value(crc_width_);

		uint32_t search_start = polynomial_ > 0 ? polynomial_ : thread_number * poly_step;

		if (verbose_) {
			std::cout << "Starting Thread " << thread_number << ", searching from ";
			std::cout << std::hex << search_start << " to " << search_end << std::endl << std::dec << std::flush;
		}

		pool.add(boost::bind(&bf_crc::brute_force, this, thread_number, search_start, search_end, test_vectors));

	}

	if (verbose_)
		std::cout << std::endl << std::flush; 

	// Wait for all threads to complete
	pool.wait();

	return crc_model_match_.size();

}

