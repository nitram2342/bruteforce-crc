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
#include <sys/time.h>
#include <iostream>
#include <fstream>
#include <list>
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

#include "bruteforce-crc.hpp"

#include "bf_crc.hpp"

#define MAX_VALUE(width) (uint32_t)((1 << width) - 1)

namespace po = boost::program_options;

static std::vector<uint32_t> expected_crcs;

unsigned int num_threads = 1;

bool verbose = true;
 
void mark_crc(size_t offs_start, size_t width) {
  size_t i, j;
  for(i = 0; i < offs_start; i++) {
    if(i> 0 && (i % 8 == 0)) 
      std::cout << "  ";
    else 
      std::cout << " ";
  }

  for(j = i; j < i + width; j++) {
    if(j> 0 && (j % 8 == 0)) 
      std::cout << " -";
    else 
      std::cout << "-";
  }
  std::cout << "\n";
}
	    
void print_message(boost::dynamic_bitset<> const& msg) {
  for(size_t i = 0; i < msg.size(); i++) {
    if((i > 0) && (i % 8 == 0)) std::cout << " ";
    std::cout << (msg[i] ? "1" : "0");
  }
  std::cout << "\n";
}


/* --------------------------------------------------------------------------

     Parsing files

   --------------------------------------------------------------------------
*/

boost::dynamic_bitset<> parse_line(std::string const& line) {
  boost::dynamic_bitset<> bits;

  //std::cout << "processing line: " << line << "\n";
  static boost::regex exp1("^\\s*[10]+", boost::regex::perl|boost::regex::icase);
  if(regex_match(line, exp1)) {
    bits.resize(line.length());

    for(size_t i = 0; i < line.length(); i++) {
      char c = line.at(i);
      if(c == '1') bits[i] = true;
      else if(c == '0') bits[i] = false;
      else goto done; // ignore garbage
    }
  }
  
 done:

  return bits;
}

std::vector<bf_crc::test_vector_t> read_file(std::string const& file, int32_t offset_message, int32_t message_length, int32_t offset_crc, int32_t crc_length) {

  	std::vector<bf_crc::test_vector_t> test_vectors;

  	std::ifstream ifs(file.c_str());
 	std::string current_line;
    
  	while(getline(ifs, current_line))
	{

		bf_crc::test_vector_t tv;
		boost::dynamic_bitset<>  msg = parse_line(current_line);

		boost::dynamic_bitset<> resized_msg;
		resized_msg.resize(message_length);

		int32_t bit = 0;
		for(int32_t i = offset_message; i < offset_message + message_length; i++) {
			resized_msg[bit++] = msg[i];
		}
		tv.message = resized_msg;

		uint32_t crc = 0;
		for(int32_t i = 0; i < crc_length; i++) {
		  crc <<= 1;
		  crc |= (msg[offset_crc + i] == true ? 1 : 0);
		}

		printf("Extracted message with crc %04x\n", crc);
		tv.crc = crc;

		test_vectors.push_back(tv);

	}

  return test_vectors;

}

/* --------------------------------------------------------------------------

     Main

   --------------------------------------------------------------------------
*/



int main(int argc, char *argv[]) {

	bf_crc *crc_bruteforce;

 	size_t width = 16;
	size_t offs_crc = 80;
	size_t start = 0;
	size_t end = offs_crc;

	uint32_t poly = 0;
	uint32_t start_poly = 0;
	uint32_t end_poly = 0;

	bool ref_in = false;
	bool ref_out = false;

	uint32_t initial = 0;
	bool probe_initial = true;

	uint32_t final_xor = 0;
	bool probe_final_xor = false;

	// Definition of program options
	// Boost program options to allow settings with call
	po::options_description desc("Allowed options");
	desc.add_options()
    ("help", "produce help message")
    ("file", po::value<std::string>(), "file containing messages")
	("output", po::value<std::string>(), "output file for matched crc settings")
	("verboce", po::value<bool>(), "verbose output")
    ("threads", po::value<unsigned int >(), "number of threads (default: 4)")
    ("width", po::value<size_t>(), "CRC width")
    ("offs-crc", po::value<size_t>(), "CRC's offset")
    ("start", po::value<size_t>(), "calculate CRC from this offset")
    ("end", po::value<size_t>(), "calculate CRC up to this offset (not included)")
	("initial", po::value<size_t>(), "set intial value (default: 0)")
    ("probe-initial", po::value<bool>(), "bruteforce the intial, overrides initial (default: true)")
    ("final-xor", po::value<uint32_t>(), "final xor (default: 0)")
    ("probe-final-xor", po::value<bool>(), "bruteforce the final-xor, overrides final-xor (default: false)")
    ("poly", po::value<uint32_t>(), "truncated poly (default: bruteforced)")
    ("reflect-in", po::value<bool>(), "reflect input (default: false)")
    ("reflect-out", po::value<bool>(), "reflect remainder output (default: false)")
    ;

	// Parse programm options
	po::variables_map vm;
	po::store(po::parse_command_line(argc, argv, desc), vm);
	po::notify(vm); 

	// Handle call for help and non-valid call
	if(vm.count("help") || !vm.count("file")) {
		std::cout << desc << std::endl;
		return 1;
	}

	// Load inputs to local variables
	if(vm.count("threads")) num_threads = vm["threads"].as<unsigned int>();
	if(vm.count("width")) width = vm["width"].as<size_t>();
	if(vm.count("offs-crc")) offs_crc = vm["offs-crc"].as<size_t>();
	if(vm.count("start")) start = vm["start"].as<size_t>();
	if(vm.count("end")) end = vm["end"].as<size_t>();
	if(vm.count("initial")) initial = vm["initial"].as<uint32_t>();
	if(vm.count("probe-initial")) probe_initial = vm["probe-initial"].as<bool>();
	if(vm.count("final-xor")) final_xor = vm["final-xor"].as<uint32_t>();
	if(vm.count("probe-final-xor")) probe_final_xor = vm["probe-final-xor"].as<bool>();
	if(vm.count("poly")) poly = vm["poly"].as<uint32_t>();
	if(vm.count("reflect-in")) ref_in = vm["reflect-in"].as<bool>();
	if(vm.count("reflect-out")) ref_out = vm["reflect-out"].as<bool>();

	// Check parameters TODO: A lot more checking
	if(width > 16) { std::cout << "maximum value for width is: 16\n"; exit(1); } // Why 16?

	// Read messages from intput file
	std::vector<bf_crc::test_vector_t> test_vectors;
 	if(vm.count("file")) {
		test_vectors = read_file(vm["file"].as<std::string>(), start, end-start, offs_crc, width);
	}

	if(vm.count("output")) {
		// creare output file
	}

	// Define search space 
	start_poly = poly > 0 ? poly : 0x0000;
	end_poly = (poly > 0 ? poly : MAX_VALUE(width));

	// Override non-conformal input
	if (probe_initial) initial = 0;

	// Warn user when things are about to go wrong TODO: Needs to be make more cleaver...
  	if(((end-start) % 8 != 0) || (end - start == 0)) {
    	std::cout << std::endl << "Warning: input reflection only works if range start ... end is N * 8 bit with N > 0" << std::endl << std::endl; 
	}

	crc_bruteforce = new bf_crc(width, 				// CRC Width
								poly, 				// Polynomial
								probe_final_xor, 	// Probe Final XOR?
								final_xor, 			// Final XOR
								probe_initial,   	// Probe Initial?
								initial, 			// Initial
								ref_in, 			// Probe Reflected Input?
								ref_out);			// Probe Reflected Output?

	crc_bruteforce->print_settings();

	int found = crc_bruteforce->do_brute_force(4, test_vectors);


/*
	int found = crc_bruteforce->do_brute_force(	width,
												poly,
												start_poly,
												end_poly,
												num_threads,
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
*/

	std::cout << "\nNo model found.\n";

	return 0;
}


