/*
 * Generate artifical telegrams and append a CRC.
 *
 * Author: Martin Schobert <schobert@sitsec.net>
 *
 */
#include <iostream>
#include <string>
#include <boost/dynamic_bitset.hpp>
#include <boost/program_options.hpp>
#include "crc.hpp"

namespace po = boost::program_options;

typedef my_crc_basic crc_t;

bool int_to_bool(int v) { 
  return v == 0 ? false : true; 
}

std::string bool_to_str(bool v) { 
  return v ? "true" : "false"; 
}

	    
uint32_t random_value(uint32_t max_val, uint32_t min_val = 0) {
  return (rand() % ((max_val-min_val)+1)) + min_val; 
}

bool random_bool() {
  return int_to_bool(random_value(1));
}

int main(int argc, char *argv[]) {

  srand((unsigned)time(0)); 

  size_t num_messages = 5;
  size_t width = random_value(16, 5);
  size_t start = random_value(0);
  size_t offs_crc = start + random_value(80, 30);
  size_t end = offs_crc;
  uint32_t poly = random_value(MAX_VALUE(width));
  uint32_t init = random_value(MAX_VALUE(width));
  uint32_t final_xor = width < 12 ? random_value(MAX_VALUE(width)) : 0;
  bool 
    ref_in = random_bool(), 
    ref_out = random_bool();

  // definition of program options
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help", "produce help message")
    ("width", po::value<size_t>(), "CRC width")
    ("messages", po::value<size_t>(), "number of messages")
    ("final-xor", po::value<uint32_t>(), "use value for the final XOR")
    ;

  // parse programm options
  po::variables_map vm;
  po::store(po::parse_command_line(argc, argv, desc), vm);
  po::notify(vm); 

  
  if(vm.count("help")) {
    std::cout << desc << "\n";
    return 1;
  }

  if(vm.count("width")) width = vm["width"].as<size_t>();
  if(vm.count("messages")) num_messages = vm["messages"].as<size_t>();
  if(vm.count("final-xor")) final_xor = vm["final-xor"].as<uint32_t>();

  // check parameters
  if(width > 16) { std::cout << "maximum value for width is: 16\n"; exit(1); }


  // print parameters
  std::cout << "# width                    : " << width << " bits\n"
	    << "# CRC's offset             : " << offs_crc << "\n"
	    << "# calc CRC for bit offsets : " << start << " .. " << end << " (not included)\n"
	    << "# final XOR                : " << final_xor << "\n"
	    << "# reflect in               : " << bool_to_str(ref_in) << "\n"
	    << "# reflect out              : " << bool_to_str(ref_out) << "\n"
	    << "# \n"
	    << "# truncated polynom        : " << poly << " (MSB not shown)\n"
	    << "# initial value            : " << init << "\n"
	    << "\n";

  crc_t crc(width, poly, init, final_xor, ref_in, ref_out);

  for(size_t num_msg = 0; num_msg < num_messages; num_msg++) {
    size_t i = 0;

    crc.reset(init);

    // the data bits
    for(i = start; i < end; i++) {
      int v = random_value(1);
      std::cout << v;
      crc.process_bit(int_to_bool(v));
    }
    std::cout << " ";

    // write crc
    uint32_t cs = crc.checksum();

    for(i = 0; i < width; i++) {
      uint32_t mask = 1 << (width-1 -i);
      int bit = (cs & mask) ? 1 : 0;
      std::cout << bit;
    }
    std::cout << "\n";
    
  }

  return 0;
}


