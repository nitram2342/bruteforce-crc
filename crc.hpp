/*
 * This is a stripped-down and partially modified version of Boost's CRC library.
 * I extracted the crc_basic class and removed the template parameter, because I
 * want to specify the original template parameter at run-time.
 *
 * Martin Schobert <schobert@sitsec.net>
 *
 * The original header:
 *
 * Boost CRC library crc.hpp header file  -----------------------------------//
 *
 * Copyright 2001, 2004 Daryle Walker.  Use, modification, and distribution are
 * subject to the Boost Software License, Version 1.0.  (See accompanying file
 * LICENSE_1_0.txt or a copy at <http://www.boost.org/LICENSE_1_0.txt>.)
 *
 *  See <http://www.boost.org/libs/crc/> for the library's home page.
 *
 */

#ifndef CRC_HPP
#define CRC_HPP

#include <boost/crc.hpp>

//  Simple cyclic redundancy code (CRC) class declaration  -------------------//

class my_crc_basic {


public:
  typedef uint32_t value_type;

  // Constructor
  explicit my_crc_basic(unsigned int width,
			value_type truncated_polynominal = 0,
			value_type initial_remainder = 0, 
			value_type final_xor_value = 0,
			bool reflect_input = false, 
			bool reflect_remainder = false );
  
  void set( value_type truncated_polynominal,
	    value_type initial_remainder = 0, 
	    value_type final_xor_value = 0,
	    bool reflect_input = false, bool 
	    reflect_remainder = false );

  void reset( value_type new_rem );
  void process_bit( bool bit );
  value_type checksum() const;

  bool calc_crc(value_type const use_initial,
		boost::dynamic_bitset<> const& msg,
		value_type const expected_crc);
void calc_crc(value_type const use_initia,
		boost::dynamic_bitset<> const& msg);

  value_type reflect(value_type  x ) const;

private:
  // Member data
  unsigned int width_;
  value_type rem_;
  value_type poly_, init_, final_;  // non-const to allow assignability
  bool rft_in_, rft_out_;     // non-const to allow assignability

  uint32_t high_bit_mask;;
  uint32_t sig_bits;

};



#endif 


