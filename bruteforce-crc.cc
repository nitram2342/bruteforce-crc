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

static std::vector<bf_crc::fast_int_t> expected_crcs;

unsigned int num_threads = 1;
	    

void extract_expected_crcs_from_messages(std::vector<bf_crc::fast_int_t> & expected_crcs,
					 bf_crc::message_list_t messages,
					 size_t offs_start, size_t len) {

  int msg_i = 0;
  expected_crcs.resize(messages.size());

  BOOST_FOREACH(bf_crc::bitset_t const& msg, messages) {
    bf_crc::fast_int_t crc = 0;
    for(size_t i = 0; i < len; i++) {
      crc <<= 1;
      crc |= (msg[offs_start + i] == true ? 1 : 0);
    }
    printf("Extracted message with crc %04x\n", crc);
    expected_crcs[msg_i] = crc;
    msg_i++;
  }
}


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
	    
void print_message(bf_crc::bitset_t const& msg) {
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

bf_crc::message_list_t read_file(std::string const& file) {

  bf_crc::message_list_t msg_list;

  std::ifstream ifs(file.c_str());
  std::string temp;
    
  while(getline(ifs, temp))
    msg_list.push_back(parse_line(temp));
  return msg_list;

}

/* --------------------------------------------------------------------------

     Main

   --------------------------------------------------------------------------
*/



int main(int argc, char *argv[]) {

	bf_crc crc_bruteforce;

 	size_t width = 16;
	size_t offs_crc = 80;
	size_t start = 0;
	size_t end = offs_crc;

	bf_crc::fast_int_t poly = 0;
	bf_crc::fast_int_t start_poly = 0;
	bf_crc::fast_int_t end_poly = 0;

	bool ref_in = false;
	bool ref_out = false;

	bf_crc::fast_int_t initial = 0;
	bool probe_initial = true;

	bf_crc::fast_int_t final_xor = 0;
	bool probe_final_xor = false;

	// Definition of program options
	// Boost program options to allow settings with call
	po::options_description desc("Allowed options");
	desc.add_options()
    ("help", "produce help message")
    ("file", po::value<std::string>(), "file containing messages")
    ("threads", po::value<unsigned int >(), "number of threads (default: 4)")
    ("width", po::value<size_t>(), "CRC width")
    ("offs-crc", po::value<size_t>(), "CRC's offset")
    ("start", po::value<size_t>(), "calculate CRC from this offset")
    ("end", po::value<size_t>(), "calculate CRC up to this offset (not included)")
	("initial", po::value<size_t>(), "set intial value (default: 0)")
    ("probe-initial", po::value<bool>(), "bruteforce the intial, overrides initial (default: true)")
    ("final-xor", po::value<bf_crc::fast_int_t>(), "final xor (default: 0)")
    ("probe-final-xor", po::value<bool>(), "bruteforce the final-xor, overrides final-xor (default: false)")
    ("poly", po::value<bf_crc::fast_int_t>(), "truncated poly (default: bruteforced)")
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
	if(vm.count("initial")) initial = vm["initial"].as<bf_crc::fast_int_t>();
	if(vm.count("probe-initial")) probe_initial = vm["probe-initial"].as<bool>();
	if(vm.count("final-xor")) final_xor = vm["final-xor"].as<bf_crc::fast_int_t>();
	if(vm.count("probe-final-xor")) probe_final_xor = vm["probe-final-xor"].as<bool>();
	if(vm.count("poly")) poly = vm["poly"].as<bf_crc::fast_int_t>();
	if(vm.count("reflect-in")) ref_in = vm["reflect-in"].as<bool>();
	if(vm.count("reflect-out")) ref_out = vm["reflect-out"].as<bool>();

	// Check parameters TODO: A lot more checking
	if(width > 16) { std::cout << "maximum value for width is: 16\n"; exit(1); } // Why 16?

	// Read messages from intput file
	bf_crc::message_list_t msg_list;
 	if(vm.count("file")) {
		msg_list = read_file(vm["file"].as<std::string>());
	}

	// Define search space
	start_poly = poly > 0 ? poly : 0x0000;
	end_poly = (poly > 0 ? poly : MAX_VALUE(width));

	// Override non-conformal input
	if (probe_initial) initial = 0;

	// Output Brute Force Paramaters
	std::cout 	<< "number of threads        : " << num_threads << std::endl
			    << "width                    : " << width << " bits" << std::endl
			    << "CRC's offset             : " << offs_crc << std::endl
	    		<< "calc CRC for bit offsets : " << start << " .. " << end << " (not included)" << std::endl
			    << "truncated polynom        : from " << start_poly << " to " << end_poly << " (MSB not shown)" << std::endl;

	if (probe_initial)
		std::cout << "initial value            : from 0 to " << MAX_VALUE(width) << std::endl;
	else
		std::cout << "initial value            : " << initial << std::endl;

	if (probe_final_xor)
		std::cout << "probe final xor          : " << bf_crc::bool_to_str(probe_final_xor) << std::endl;
	else
		std::cout << "final xor                : " << final_xor << std::endl;

	std::cout	<< "probe reflect in         : " << bf_crc::bool_to_str(ref_in) << std::endl
			    << "probe reflect out        : " << bf_crc::bool_to_str(ref_out) << std::endl
			    << std::endl;

	// Extract expected CRCs for each message
	extract_expected_crcs_from_messages(expected_crcs, msg_list, offs_crc, width);

	// Calculate number of crc calculations
	crc_bruteforce.crc_steps = poly > 0 ? 1 : 1+MAX_VALUE(width); // number of polys
	if (probe_initial)
		crc_bruteforce.crc_steps *= 1+MAX_VALUE(width); // number of inits
	if(ref_in) crc_bruteforce.crc_steps *= 2;
	if(ref_out) crc_bruteforce.crc_steps *= 2;
	if(probe_final_xor) crc_bruteforce.crc_steps *= 1+MAX_VALUE(width);


	// Warn user when things are about to go wrong TODO: Needs to be make more cleaver...
  	if(((end-start) % 8 != 0) || (end - start == 0)) {
    	std::cout << std::endl << "Warning: input reflection only works if range start ... end is N * 8 bit with N > 0" << std::endl << std::endl; 
	}

	int found = crc_bruteforce.do_brute_force(	width,
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

	std::cout << "\nNo model found.\n";

	return 0;
}


