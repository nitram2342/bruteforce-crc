//
// Test vectors generated from the crc-catalogue:
// http://reveng.sourceforge.net/crc-catalogue/
//

#include <cstdio>
#include <iostream>
#include <list>
#include <boost/dynamic_bitset.hpp>

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "Test the CRC engine"
#include <boost/test/unit_test.hpp>

#include "../crc.hpp"
#include "../bf_crc.hpp"


char getRandomChar(){
    static char c = 'A' + rand()%24;
    return c;    
}

boost::dynamic_bitset<> convert_to_bitset(uint8_t array[], size_t size) {

	boost::dynamic_bitset<> retVal(size*8);

	for (unsigned int i = 0; i < size; i++)
		for (int j = 0; j < 8; j++)
			retVal[i*8+j] = (array[i] >> (7-j)) & 0x1 ? true : false;

	return retVal;
}

BOOST_AUTO_TEST_CASE(crcSixteen)
{
	// 16 bit CRC's
	bf_crc crc_bruteforce;
	typedef boost::dynamic_bitset<> dbType;
	uint16_t width = 16;
	bf_crc::crc_t crc(width);
	dbType msg;

	// Lets make sure things are random
	srand((unsigned)time(0));

	bf_crc::message_list_t msg_list;
	std::vector<bf_crc::fast_int_t> crc_list;

	/*
	 * CRC-16/CCITT-FALSE
	 * width=16 poly=0x1021 init=0xffff refin=false refout=false xorout=0x0000 check=0x29b1 name="CRC-16/CCITT-FALSE"
	 */
/*
	uint8_t data_1[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x30}; 
	msg = convert_to_bitset(data_1, 9);
	crc.set(0x8005, // Poly
			0x0000, // Initial (Overwritten)
			0x0000, // Final XOR
			true,  // Reflect input
			true); // Reflect output
	crc.calc_crc(	0x0000, 			// Initial
			    	msg,				// Data
			    	0,					// Start offset
			    	sizeof(data_1)*8,	// End data (# of bits)
			    	0xBB3D);			// Expected CRC - not required

	msg_list.push_back(msg);
	crc_list.push_back(crc.checksum()); */

	// REVENG Check
	uint8_t data_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}; 
	msg = convert_to_bitset(data_0, 9);
	crc.set(0x8005, // Poly
			0x0000, // Initial (Overwritten)
			0x0000, // Final XOR
			true,  // Reflect input
			true); // Reflect output
	crc.calc_crc(	0x0000, 			// Initial
			    	msg,				// Data
			    	0,					// Start offset
			    	sizeof(data_0)*8,	// End data (# of bits)
			    	0xBB3D);			// Expected CRC - not required

	msg_list.push_back(msg);
	crc_list.push_back(crc.checksum());


	for (int i = 0; i < 10; i++) 
	{

		uint8_t data[9];
		for (int b = 0; b < 9; b++)
		{
			data[b] = getRandomChar();
		}

		msg = convert_to_bitset(data, 9);
		crc.set(0x8005, // Poly
				0x0000, // Initial (Overwritten)
				0x0000, // Final XOR
				true,  // Reflect input
				true); // Reflect output
		crc.calc_crc(	0x0000, 			// Initial
						msg,				// Data
						0,					// Start offset
						sizeof(data)*8,	// End data (# of bits)
						0xBB3D);			// Expected CRC - not required

		msg_list.push_back(msg);
		crc_list.push_back(crc.checksum());

	}


	// Calculate number of crc calculations
	crc_bruteforce.crc_steps = 1+(uint32_t)((1 << width) - 1); // number of polys
	crc_bruteforce.crc_steps *= 1+(uint32_t)((1 << width) - 1); // number of inits
	crc_bruteforce.crc_steps *= 2;
	crc_bruteforce.crc_steps *= 2;

	int found = crc_bruteforce.do_brute_force(	width,
												0, //poly,
												0, //start_poly,
												(uint32_t)((1 << width) - 1), //end_poly,
												4, //num_threads,
												0,//final_xor,
												0,//initial,
												0,//start,
												9*8,//end,
												msg_list,
												crc_list,
												false,//probe_final_xor,
												true,//probe_initial,
												true, //ref_in,
												true); //ref_out);

	BOOST_CHECK(1 == 1);

}


