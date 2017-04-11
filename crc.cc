
#include <iostream>

#include <boost/dynamic_bitset.hpp>
#include "crc.hpp"

//  Simple CRC class function definitions  -----------------------------------//

my_crc_basic::my_crc_basic( unsigned int width,
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


void my_crc_basic::calc_crc(value_type const use_initial,
			    boost::dynamic_bitset<> const & msg) {
  this->calc_crc(use_initial, msg, 0, AUTO);
}

bool my_crc_basic::calc_crc(value_type const use_initial,
			    boost::dynamic_bitset<> const& msg,
			    value_type const expected_crc,
			    FEED_TYPE feed_type) {
  
  reset(use_initial);	


  if(feed_type == AUTO) {
    if(rft_in_) {
      if (msg.size() % 8 != 0) feed_type = LINEAR_REVERSED;
      else feed_type = BYTEWISE_REVERSED;
    }
    else {
      feed_type = LINEAR_FORWARD;
    }
  }


  
  if(feed_type == LINEAR_FORWARD) {
    for (size_t i = 0; i < msg.size(); i++) {
      process_bit(msg[i]);
    }
  }
  else if(feed_type == LINEAR_REVERSED) {
    for (int i = msg.size()-1; i >= 0; i--) {
      process_bit(msg[i]);
    }
  }
  else if(feed_type == BYTEWISE_REVERSED) {

      for(size_t i = 0; i < msg.size(); i+=8) {
	// inverse feeding
	for(int j = 1; j <= 8; j++)
	  process_bit(msg[i + 8 - j]);
      }
  }
  
  return checksum() == expected_crc;
}


bool my_crc_basic::calc_crc(value_type const use_initial,
			    uint8_t msg[], size_t msg_length,
			    value_type const expected_crc) {
  
	reset(use_initial);	

	//process_bytes(msg, msg_length);

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

