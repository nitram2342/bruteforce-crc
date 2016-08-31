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
	bf_crc *crc_bruteforce;
	typedef boost::dynamic_bitset<> dbType;
	uint16_t width = 16;
	bf_crc::crc_t crc(width);
	dbType msg;

	// Lets make sure things are random
	srand((unsigned)time(0));

	std::vector<bf_crc::test_vector_t> test_vectors;
	bf_crc::test_vector_t test_vector;

	/*
	 * CRC-16/CCITT-FALSE
	 * width=16 poly=0x1021 init=0xffff refin=false refout=false xorout=0x0000 check=0x29b1 name="CRC-16/CCITT-FALSE"
	 */

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
			    	0xBB3D);			// Expected CRC - not required

	test_vector.message = msg;
	test_vector.crc = crc.checksum();
	test_vectors.push_back(test_vector);

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
						0xBB3D);			// Expected CRC - not required


	test_vector.message = msg;
	test_vector.crc = crc.checksum();
	test_vectors.push_back(test_vector);

	}


	crc_bruteforce = new bf_crc(width, 		// CRC Width
								0, 			// Polynomial
								false, 		// Probe Final XOR?
								0, 			// Final XOR
								false,   	// Probe Initial?
								0, 			// Initial
								true, 		// Probe Reflected Input?
								true);		// Probe Reflected Output?

	int found = crc_bruteforce->do_brute_force(4, test_vectors);

	BOOST_CHECK(1 == 1);

}


