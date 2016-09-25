/*
 * Front end application for brute-forcing CRC's of known good
 * test vectors.
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
#include <boost/filesystem.hpp>

#include "bruteforce-crc.hpp"

#include "bf_crc.hpp"

namespace po = boost::program_options;

/*
 * Parse a line from a text file for binary sequence
 */
boost::dynamic_bitset<> parse_line(std::string const& line) {

	boost::dynamic_bitset<> bits;
	static boost::regex exp1("^\\s*[10]+", boost::regex::perl|boost::regex::icase);

	if(regex_match(line, exp1)) {
		bits.resize(line.length());
		for(size_t i = 0; i < line.length(); i++) {
			char c = line.at(i);
			if(c == '1') bits[i] = true;
			else if(c == '0') bits[i] = false;
			else break; // ignore garbage
		}
	}

	return bits;
}

/*
 * Read a file of test vectors
 * Each line is a binary sequence with a message of length (message_length) starting at zero indexed offset (offset_message)
 * The CRC is of length (crc_length) located at zero indexed offset (offset_crc)
 */
std::vector<bf_crc::test_vector_t> read_file(std::string const& file, size_t offset_message, size_t message_length, size_t offset_crc, size_t crc_length, bool verbose) {

	std::vector<bf_crc::test_vector_t> test_vectors;
	std::ifstream ifs(file.c_str());
	std::string current_line;
    
	while(getline(ifs, current_line)) {
		bf_crc::test_vector_t tv;
		boost::dynamic_bitset<> msg = parse_line(current_line);
		boost::dynamic_bitset<> resized_msg;

		if(msg.size() < message_length) {
		  std::cout << "Warning: ignoring line from input file\n";
		  continue;
		}

		resized_msg.resize(message_length);
		size_t bit = 0;

		for(size_t i = offset_message; i < offset_message + message_length; i++) {
		  assert(i < msg.size());
		  assert(bit < message_length);
		  resized_msg[bit++] = msg[i];
		}

		tv.message = resized_msg;

		uint32_t crc = 0;
		for(size_t i = 0; i < crc_length; i++) {
		  assert(offset_crc + 1 < msg.size());
			crc <<= 1;
			crc |= (msg[offset_crc + i] == true ? 1 : 0);
		}

		if (verbose) {
			printf("Extracted message with crc %04x\n", crc);
		}

		tv.crc = crc;
		test_vectors.push_back(tv);
	}
	if (verbose) {
	  printf("Extracted %ld messages and CRC values\n", test_vectors.size());
	}

	return test_vectors;
}

int main(int argc, char *argv[]) {

	bf_crc *crc_bruteforce;

 	size_t crc_width = 16;
	size_t offs_crc = 80;
	size_t start = 0;
	size_t end = offs_crc;

	std::string output = "";
	bool verbose = false;

	int num_threads = 4;

	uint32_t polynomial = 0;

	bool reflected_input = false;
	bool reflected_output = false;

	uint32_t initial = 0;
	bool probe_initial = true;

	uint32_t final_xor = 0;
	bool probe_final_xor = false;

	// Definition of program options
	// Boost program options to allow settings with call
	po::options_description desc("Allowed options [required *]");
	desc.add_options()
    ("help", 													"Produce help message")
    ("file", 					po::value<std::string>(), 		"* File containing messages")
    ("width",					po::value<size_t>(), 			"* CRC width")
    ("offs-crc", 				po::value<size_t>(), 			"* CRC's offset")
    ("start", 					po::value<size_t>(), 			"* Calculate CRC from this offset")
    ("end", 					po::value<size_t>(), 			"* Calculate CRC up to this offset (not included)")

	("output", 					po::value<std::string>(), 		"Output file for matched crc settings")
	("verbose", 				po::value<bool>(), 				"Enable verbose output")

    ("poly", 					po::value<uint32_t>(), 			"Truncated polynomial (default: bruteforced)")
	("poly-start",				po::value<uint32_t>(),			"Start of polynomial search space (default: 0)")
	("poly-end",				po::value<uint32_t>(),			"End of polynomial search space (default (2^width - 1))")
    
	("threads", 				po::value<unsigned int >(), 	"Number of threads (default: 4)")
	("initial", 				po::value<size_t>(), 			"Set intial value (default: 0)")

    ("probe-initial", 			po::value<bool>(), 				"Bruteforce the intial, overrides initial (default: true)")
    ("final-xor", 				po::value<uint32_t>(), 			"Final xor (default: 0)")
    ("probe-final-xor",			po::value<bool>(), 				"Bruteforce the final-xor, overrides final-xor (default: false)")
    ("probe-reflected-input", 	po::value<bool>(), 				"Probe for reflect input (default: false)")
    ("probe-reflected-output", 	po::value<bool>(), 				"Probe for reflect remainder output (default: false)")
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
	if(vm.count("output"))						output				= vm["output"].as<std::string>();
	if(vm.count("verbose"))						verbose				= vm["verbose"].as<bool>();
	if(vm.count("threads")) 					num_threads 		= vm["threads"].as<unsigned int>();
	if(vm.count("width")) 						crc_width 			= vm["width"].as<size_t>();
	if(vm.count("offs-crc"))	 				offs_crc 			= vm["offs-crc"].as<size_t>();
	if(vm.count("start")) 						start 				= vm["start"].as<size_t>();
	if(vm.count("end")) 						end 				= vm["end"].as<size_t>();
	if(vm.count("initial")) 					initial 			= vm["initial"].as<uint32_t>();
	if(vm.count("probe-initial")) 				probe_initial 		= vm["probe-initial"].as<bool>();
	if(vm.count("final-xor")) 					final_xor			= vm["final-xor"].as<uint32_t>();
	if(vm.count("probe-final-xor")) 			probe_final_xor		= vm["probe-final-xor"].as<bool>();
	if(vm.count("poly")) 						polynomial			= vm["poly"].as<uint32_t>();
	if(vm.count("probe-reflected-input")) 		reflected_input		= vm["probe-reflected-input"].as<bool>();
	if(vm.count("probe-reflected-output"))	 	reflected_output	= vm["probe-reflected-output"].as<bool>();

	// Check parameters: A lot more checking
	if(crc_width > 32) { std::cout << "Error: maximum value for width is 32" << std::endl; exit(1); }
	
	// Warn user when things are about to go wrong TODO: Needs to be make more cleaner...
  	if(((end-start) % 8 != 0) || (end - start == 0)) {
    	std::cout << std::endl << "Warning: input reflection only works if range start ... end is N * 8 bit with N > 0" << std::endl << std::endl; 
		std::cout << std::flush;
	}

	// Read messages from intput file
	std::vector<bf_crc::test_vector_t> test_vectors;
 	if(vm.count("file")) {
	  std::string const & fname = vm["file"].as<std::string>();
	  if(!boost::filesystem::exists(fname)) {
	    std::cout << "Can't find file '" << fname << "'." << std::endl;
	    exit(1);
	  }
	  else
	    test_vectors = read_file(fname, start, end-start, offs_crc, crc_width, verbose);
	}

	// Override non-conformal input
	if (probe_initial) initial = 0;

	crc_bruteforce = new bf_crc(crc_width, 			// CRC Width
								polynomial, 		// Polynomial
								probe_final_xor, 	// Probe Final XOR?
								final_xor, 			// Final XOR
								probe_initial,   	// Probe Initial?
								initial, 			// Initial
								reflected_input, 	// Probe Reflected Input?
								reflected_output);	// Probe Reflected Output?

	// The command line input can limit the search range
	if (vm.count("poly-start")) {
		uint32_t poly_start = vm["poly-start"].as<uint32_t>();
		crc_bruteforce->set_polynomial_start(poly_start);
	}

	if (vm.count("poly-end")) {
		uint32_t poly_end = vm["poly-end"].as<uint32_t>();
		crc_bruteforce->set_polynomial_end(poly_end);
	}

	crc_bruteforce->set_verbose(verbose);
		
	int found = crc_bruteforce->do_brute_force(num_threads, test_vectors);

	if (found > 0)
		std::cout << "Found " << found << " matches." << std::endl << std::endl;
	else
		std::cout << "No model found." << std::endl << std::endl;

	// Set output file
	if(vm.count("output")) {
		std::vector<bf_crc::crc_model_t> models = crc_bruteforce->crc_model_match();
		try {
			std::ofstream ofile;
			std::string file = vm["output"].as<std::string>();
			ofile.open(file.c_str());
			ofile << "Polynomial, Initial, Final XOR, Reflected Input, Reflected Output" << std::endl;
			for (size_t i = 0; i < models.size(); i++) {
				ofile << std::hex << "0x" << models[i].polynomial << "," << std::dec;
				ofile << std::hex << "0x" << models[i].initial << "," << std::dec;
				ofile << std::hex << "0x" << models[i].final_xor << "," << std::dec;
				ofile << (models[i].reflected_input ? "true" : "false") << ",";
				ofile << (models[i].reflected_output ? "true" : "false") << std::endl;
			}
			ofile.close();
		} catch (...) { }
			
	}

	return 0;
}


