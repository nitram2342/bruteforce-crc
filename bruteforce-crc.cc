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

#include "crc.hpp"
#include "ThreadPool.h"

#define MAX_VALUE(width) (uint32_t)((1 << width) - 1)

namespace po = boost::program_options;

typedef boost::dynamic_bitset<> bitset_t;
typedef std::vector<bitset_t> message_list_t;


typedef uint32_t fast_int_t;
typedef my_crc_basic crc_t;

static std::vector<fast_int_t> expected_crcs;


boost::mutex mymutex;
uint64_t crc_steps = 0;
uint64_t crc_counter = 0;
struct timeval start_time, current_time;
unsigned int num_threads = 4;

struct bruteforce_params {
  unsigned int _width;
  uint32_t _start_poly, _end_poly;
  uint32_t _final_xor;
  uint32_t _initial;
  bool _ref_in, _ref_out;
  size_t _start, _end; // message offsets
  message_list_t const & _msg_list;
  std::vector<fast_int_t> const & _expected_crcs;
  bool _probe_final_xor;
  bool _probe_initial;

  bruteforce_params(unsigned int width,
		    uint32_t start_poly, 
		    uint32_t end_poly,
		    uint32_t final_xor,
		    uint32_t initial,
		    bool ref_in, 
		    bool ref_out,
		    size_t start, 
		    size_t end,
		    message_list_t const & msg_list,
		    std::vector<fast_int_t> const & expected_crcs,
		    bool probe_final_xor,
			bool probe_initial) 
    : _width(width),
      _start_poly(start_poly),
      _end_poly(end_poly),
      _final_xor(final_xor),
      _initial(initial),
      _ref_in(ref_in),
      _ref_out(ref_out),
      _start(start),
      _end(end),
      _msg_list(msg_list),
      _expected_crcs(expected_crcs),
      _probe_final_xor(probe_final_xor),
      _probe_initial(probe_initial) {}
};

int bool_to_int(bool v) { 
  return v ? 1 : 0; 
}

bool int_to_bool(int v) { 
  return v == 0 ? false : true; 
}

std::string bool_to_str(bool v) { 
  return v ? "true" : "false"; 
}

std::string number_to_str(uint64_t v) {
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

uint64_t get_delta_time_in_ms(struct timeval const& start) {
  struct timeval end;
  gettimeofday(&end, NULL);  
  return (end.tv_sec*1000 + end.tv_usec/1000.0) - (start.tv_sec*1000 + start.tv_usec/1000.0); 
}

void show_hit(uint32_t poly, uint32_t init, struct bruteforce_params const& p) {
  std::cout
    << "----------------------[ MATCH ]--------------------------------\n"
    << "Found a model for the CRC calculation:\n"
    << "Truncated polynom : 0x" << std::hex << poly << " (" << std::dec << poly << ")\n"
    << "Initial value     : 0x" << std::hex << init << " (" << std::dec << init << ")\n"
    << "Final XOR         : 0x" << std::hex << p._final_xor << " (" << std::dec << p._final_xor << ")\n"
    << "Reflected input   : " << bool_to_str(p._ref_in) << "\n"
    << "Reflected output  : " << bool_to_str(p._ref_out) << "\n"
    << "Message offset    : from bit " << p._start << " .. " << p._end << " (end not included)\n"
    << "\n";
}

void print_stats() {
  
  if(get_delta_time_in_ms(current_time) > 5000) {

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

bool brute_force(struct bruteforce_params p) {
  
	// Get a CRC checker
	crc_t crc(p._width);
	uint32_t init = 0;

	for(uint32_t poly = p._start_poly; poly < p._end_poly && poly <= MAX_VALUE(p._width); poly++) {

		for(uint32_t final_xor = (p._probe_final_xor ? 0 : p._final_xor); final_xor <= (p._probe_final_xor ? MAX_VALUE(p._width) : p._final_xor); final_xor++) {

			crc.set(poly, 0, final_xor, p._ref_in, p._ref_out);

			for(init = 0; init <= MAX_VALUE(p._width); init++) {

				bool match = true;
				size_t m_i;

				for(m_i = 0; match && (m_i < p._msg_list.size()); m_i++) {
					match = crc.calc_crc(init, p._msg_list[m_i], p._start, p._end, p._expected_crcs[m_i]);
				}

				if(m_i == p._msg_list.size()) {
					show_hit(poly, init, p);
					//exit(0);
				}
			}


			boost::mutex::scoped_lock mylock(mymutex);
			crc_counter += MAX_VALUE(p._width);

			if(p._probe_final_xor || (poly % 0x80 == 0))
				print_stats();
		}
	}
	return false;
}
	    

void extract_expected_crcs_from_messages(std::vector<fast_int_t> & expected_crcs,
					 message_list_t messages,
					 size_t offs_start, size_t len) {

  int msg_i = 0;
  expected_crcs.resize(messages.size());

  BOOST_FOREACH(bitset_t const& msg, messages) {
    fast_int_t crc = 0;
    for(size_t i = 0; i < len; i++) {
      crc <<= 1;
      crc |= (msg[offs_start + i] == true ? 1 : 0);
    }
    printf("extracted crc %04x\n", crc);
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
	    
void print_message(bitset_t const& msg) {
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

message_list_t read_file(std::string const& file) {

  message_list_t msg_list;

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

 	size_t width = 16;
	size_t offs_crc = 80;
	size_t start = 0;
	size_t end = offs_crc;

	fast_int_t poly = 0;
	fast_int_t start_poly = 0;
	fast_int_t end_poly;

	bool ref_in = false;
	bool ref_out = false;

	fast_int_t initial = 0;
	bool probe_initial = true;

	fast_int_t final_xor = 0;
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
    ("final-xor", po::value<fast_int_t>(), "final xor (default: 0)")
    ("probe-final-xor", po::value<bool>(), "bruteforce the final-xor, overrides final-xor (default: false)")
    ("poly", po::value<fast_int_t>(), "truncated poly (default: bruteforced)")
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
	if(vm.count("initial")) initial = vm["initial"].as<fast_int_t>();
	if(vm.count("probe-initial")) probe_initial = vm["probe-initial"].as<bool>();
	if(vm.count("final-xor")) final_xor = vm["final-xor"].as<fast_int_t>();
	if(vm.count("probe-final-xor")) probe_final_xor = vm["probe-final-xor"].as<bool>();
	if(vm.count("poly")) poly = vm["poly"].as<fast_int_t>();
	if(vm.count("reflect-in")) ref_in = vm["reflect-in"].as<bool>();
	if(vm.count("reflect-out")) ref_out = vm["reflect-out"].as<bool>();

	// Check parameters TODO: A lot more checking
	if(width > 16) { std::cout << "maximum value for width is: 16\n"; exit(1); } // Why 16?

	// Read messages from intput file
	message_list_t msg_list;
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
			    << "final XOR                : " << final_xor << std::endl
			    << "truncated polynom        : from " << start_poly << " to " << end_poly << " (MSB not shown)" << std::endl;

	if (probe_initial)
		std::cout << "initial value            : from 0 to " << MAX_VALUE(width) << std::endl;
	else
		std::cout << "initial value            : " << initial << std::endl;

	if (probe_final_xor)
		std::cout << "probe final xor          : " << bool_to_str(probe_final_xor) << std::endl;
	else
		std::cout << "final xor          : " << final_xor << std::endl;

	std::cout	<< "probe reflect in         : " << bool_to_str(ref_in) << std::endl
			    << "probe reflect out        : " << bool_to_str(ref_out) << std::endl
			    << std::endl;

	// Extract expected CRCs for each message
	extract_expected_crcs_from_messages(expected_crcs, msg_list, offs_crc, width);

	// Calculate number of crc calculations
	crc_steps = poly > 0 ? 1 : 1+MAX_VALUE(width); // number of polys
	if (probe_initial)
		crc_steps *= 1+MAX_VALUE(width); // number of inits
	if(ref_in) crc_steps *= 2;
	if(ref_out) crc_steps *= 2;
	if(probe_final_xor) crc_steps *= 1+MAX_VALUE(width);

	// For statistics
	gettimeofday(&start_time, NULL);
	gettimeofday(&current_time, NULL);


  	if(((end-start) % 8 != 0) || (end - start == 0)) {
    	std::cout << "input reflection only works if range start ... end is N * 8 bit with N > 0\n"; 
	 //   exit(1);
	}

	ThreadPool<boost::function0<void> > pool;
	int poly_step = poly > 0 ? 1 : MAX_VALUE(width)/num_threads;

	for(int probe_ref_in = 0; probe_ref_in <= bool_to_int(ref_in); probe_ref_in++) {

	    for(int probe_ref_out = 0; probe_ref_out <= bool_to_int(ref_out); probe_ref_out++) {

			// Step through search space, assigning a batch of polynomials to each thread 
			// (poly_step polynomials per thread)
			for(uint32_t _poly = start_poly; _poly <= end_poly; _poly += poly_step) {
	
				struct bruteforce_params p(	width, 
											_poly, 
											_poly + poly_step, 
											final_xor, 
											initial,
							   				int_to_bool(probe_ref_in), 
											int_to_bool(probe_ref_out),
											start, 
											end,
											msg_list, 
											expected_crcs,
							   				probe_final_xor,
											probe_initial);
	
				pool.add(boost::bind(&brute_force, p));

			}

		}

  	}

	pool.wait();

	std::cout << "\nNo model found.\n";

	return 0;
}


