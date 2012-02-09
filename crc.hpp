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
  explicit my_crc_basic(uint width,
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
		size_t offs_start,
		size_t offs_end,
		value_type const expected_crc);

  value_type reflect(value_type  x ) const;

private:
  // Member data
  uint width_;
  value_type rem_;
  value_type poly_, init_, final_;  // non-const to allow assignability
  bool rft_in_, rft_out_;     // non-const to allow assignability

  uint32_t high_bit_mask;;
  uint32_t sig_bits;

};


//  Simple CRC class function definitions  -----------------------------------//

my_crc_basic::my_crc_basic( uint width,
			    my_crc_basic::value_type  truncated_polynominal,
			    my_crc_basic::value_type  initial_remainder,      // = 0
			    my_crc_basic::value_type  final_xor_value,        // = 0
			    bool                                  reflect_input,          // = false
			    bool                                  reflect_remainder       // = false
				  )
  : width_(width), rem_( initial_remainder ), poly_( truncated_polynominal )
  , init_( initial_remainder ), final_( final_xor_value )
  , rft_in_( reflect_input ), rft_out_( reflect_remainder )
{
  high_bit_mask = 1ul << ( width - 1u );
  sig_bits = (~( ~( 0ul ) << width )) ;
  
}

void my_crc_basic::set(my_crc_basic::value_type  truncated_polynominal,
		       my_crc_basic::value_type  initial_remainder,      // = 0
		       my_crc_basic::value_type  final_xor_value,        // = 0
		       bool                                  reflect_input,          // = false
		       bool                                  reflect_remainder       // = false
		       ) {
  rem_ = initial_remainder;
  poly_ =  truncated_polynominal;
  init_ = initial_remainder;
  final_ = final_xor_value;
  rft_in_ = reflect_input;
  rft_out_ = reflect_remainder;
}



void my_crc_basic::reset(my_crc_basic::value_type  new_rem) {
    rem_ = new_rem;
}


void my_crc_basic::process_bit (bool bit) {

  // compare the new bit with the remainder's highest
  rem_ ^= ( bit ? high_bit_mask : 0u );

  // a full polynominal division step is done when the highest bit is one
  bool const  do_poly_div = static_cast<bool>( rem_ & high_bit_mask );
  
  // shift out the highest bit
  rem_ <<= 1;
  
  // carry out the division, if needed
  if ( do_poly_div ) rem_ ^= poly_;
 
}


my_crc_basic::value_type my_crc_basic::checksum() const {
  return ( (rft_out_ ? reflect( rem_ ) : rem_)
	   ^ final_ ) & sig_bits;
}


bool my_crc_basic::calc_crc(value_type const use_initial,
			    boost::dynamic_bitset<> const& msg,
			    size_t offs_start,
			    size_t offs_end,
			    value_type const expected_crc) {
  
  reset(use_initial);	
  
  for(size_t i = offs_start; i < offs_end; i++) {
    process_bit(msg[i]);
  }
  return checksum() == expected_crc;
}



// Function that reflects its argument
my_crc_basic::value_type my_crc_basic::reflect(value_type  x ) const {

  value_type        reflection = 0;
  value_type const  one = 1;
  
  for( std::size_t i = 0 ; i < width_ ; ++i, x >>= 1 ) {
    if ( x & one ) {
      reflection |= ( one << (width_ - 1u - i) );
    }
  }
  
  return reflection;
}


#endif 


