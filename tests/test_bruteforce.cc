/*
 * Test vectors generated from the crc-catalogue:
 * http://reveng.sourceforge.net/crc-catalogue/
 *
 *                 Copyright MartynP 2016.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 */

#include <cstdio>
#include <iostream>
#include <list>
#include <boost/dynamic_bitset.hpp>

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "Test the bruteforce functionality"
#include <boost/test/unit_test.hpp>

#include "../crc.hpp"
#include "../bf_crc.hpp"


char getRandomChar(){
    static char c = 'A' + rand()%24;
    return c;    
}

BOOST_AUTO_TEST_CASE(crcFourteen)
{
	// 14 bit CRC's
	bf_crc *crc_bruteforce;
	typedef boost::dynamic_bitset<> dbType;
	uint16_t crc_width = 14;
	bf_crc::crc_t crc(crc_width);
	dbType msg;

	// Lets make sure things are random
	srand((unsigned)time(0));

	std::vector<bf_crc::test_vector_t> test_vectors;
	bf_crc::test_vector_t test_vector;

	/*
	 * CRC-14/DARC
	 * width=14 poly=0x0805 init=0x0000 refin=true refout=true xorout=0x0000 check=0x082d name="CRC-14/DARC"
	 */

	// REVENG Check
	uint8_t data_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}; 
	msg = bf_crc::convert_uint8_to_bitset(data_0, 9);
	crc.set(0x0805, // Poly
			0x0000, // Initial (Overwritten)
			0x0000, // Final XOR
			true,  // Reflect input
			true); // Reflect output
	crc.calc_crc(	0x0000, 			// Initial
			    	msg,				// Data
			    	0x082D);			// Expected CRC - not required

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

		msg = bf_crc::convert_uint8_to_bitset(data, 9);
		crc.set(0x805, // Poly
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


	crc_bruteforce = new bf_crc(crc_width, 		// CRC Width
								0, 			// Polynomial
								false, 		// Probe Final XOR?
								0, 			// Final XOR
								true,   	// Probe Initial?
								0, 			// Initial
								true, 		// Probe Reflected Input?
								true);		// Probe Reflected Output?

	int found = crc_bruteforce->do_brute_force(4, test_vectors);

	BOOST_CHECK(1 == 1);

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
	msg = bf_crc::convert_uint8_to_bitset(data_0, 9);
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

		msg = bf_crc::convert_uint8_to_bitset(data, 9);
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

BOOST_AUTO_TEST_CASE(crcThirtyTwo)
{
	// 32 bit CRC's
	bf_crc *crc_bruteforce;
	typedef boost::dynamic_bitset<> dbType;
	uint16_t crc_width = 32;
	bf_crc::crc_t crc(crc_width);
	dbType msg;

	// Lets make sure things are random
	srand((unsigned)time(0));

	std::vector<bf_crc::test_vector_t> test_vectors;
	bf_crc::test_vector_t test_vector;

	/*
	 * CRC-32/BZIP2
	 * width=32 poly=0x04c11db7 init=0xffffffff refin=false refout=false xorout=0xffffffff check=0xfc891918 name="CRC-32/BZIP2"
	 */

	// REVENG Check
	uint8_t data_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}; 
	msg = bf_crc::convert_uint8_to_bitset(data_0, 9);
	crc.set(0x04C11db7, // Poly
			0xFFFFFFFF, // Initial (Overwritten)
			0xFFFFFFFF, // Final XOR
			false,  // Reflect input
			false); // Reflect output
	crc.calc_crc(	0xFFFFFFFF, 			// Initial
			    	msg,				// Data
			    	0x0);			// Expected CRC - not required

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

		msg = bf_crc::convert_uint8_to_bitset(data, 9);
		crc.set(0x04C11DB7, // Poly
				0xFFFFFFFF, // Initial (Overwritten)
				0xFFFFFFFF, // Final XOR
				false,  // Reflect input
				false); // Reflect output
		crc.calc_crc(	0xFFFFFFFF, 			// Initial
						msg,				// Data
						0x0);			// Expected CRC - not required


	test_vector.message = msg;
	test_vector.crc = crc.checksum();
	test_vectors.push_back(test_vector);

	}

	crc_bruteforce = new bf_crc(crc_width, 		// CRC Width
								0, 			// Polynomial
								false, 		// Probe Final XOR?
								0xFFFFFFFF, 			// Final XOR
								false,   	// Probe Initial?
								0xFFFFFFFF, 			// Initial
								false, 		// Probe Reflected Input?
								false);		// Probe Reflected Output?
	crc_bruteforce->set_verbose(true);
	int found = crc_bruteforce->do_brute_force(4, test_vectors);

	BOOST_CHECK(1 == 1);

}


