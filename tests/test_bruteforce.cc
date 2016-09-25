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

#define CRCFOURTEEN
#define CRCSIZTEEN
#define CRCTHIRTYTWO

char getRandomChar(){
    static char c = 'A' + rand()%24;
    return c;    
}

uint32_t calculate_crc(uint32_t crc_width, uint8_t data[], size_t length, bf_crc::crc_model_t model)
{
	bf_crc::crc_t crc(crc_width);
	boost::dynamic_bitset<> msg = bf_crc::convert_uint8_to_bitset(data, length);

	crc.set(model.polynomial, model.initial, model.final_xor, model.reflected_input, model.reflected_output);
	crc.calc_crc(model.initial, msg);
	
	return crc.checksum();
}

uint32_t calculate_crc(uint32_t crc_width, uint8_t data[], size_t length, bf_crc::crc_model_t model, boost::dynamic_bitset<> *msg)
{
	bf_crc::crc_t crc(crc_width);
	
	*msg = bf_crc::convert_uint8_to_bitset(data, length);

	crc.set(model.polynomial, model.initial, model.final_xor, model.reflected_input, model.reflected_output);
	crc.calc_crc(model.initial, *msg);
	
	return crc.checksum();
}

#ifdef CRCFOURTEEN
BOOST_AUTO_TEST_CASE(crcFourteen)
{
	// 14 bit CRC's
	bf_crc *crc_bruteforce;
	uint16_t crc_width = 14;
	bf_crc::crc_t crc(crc_width);
	boost::dynamic_bitset<> msg;

	// Lets make sure things are random
	srand((unsigned)time(0));

	std::vector<bf_crc::test_vector_t> test_vectors;
	bf_crc::test_vector_t test_vector;

	/*
	 * CRC-14/DARC
	 * width=14 poly=0x0805 init=0x0000 refin=true refout=true xorout=0x0000 check=0x082d name="CRC-14/DARC"
	 */

	bf_crc::crc_model_t model(0x0805, 0x0000, 0x0000, true, true);

	// REVENG Check
	uint8_t data_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}; 
	test_vector.crc = calculate_crc(crc_width, data_0, sizeof(data_0), model, (boost::dynamic_bitset<>*)&msg);
	test_vector.message = msg;
	test_vectors.push_back(test_vector);

	// Check the CRC engine is still working...
	BOOST_CHECK(test_vector.crc == 0x082D);

	for (int i = 0; i < 10; i++) {

		uint8_t data[9];
		for (int b = 0; b < 9; b++)
			data[b] = getRandomChar();

		test_vector.crc = calculate_crc(crc_width, data, sizeof(data_0), model, (boost::dynamic_bitset<>*)&msg);
		test_vector.message = msg;
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
	crc_bruteforce->set_verbose(true);
	crc_bruteforce->do_brute_force(4, test_vectors);

	// Get results
	std::vector<bf_crc::crc_model_t> results = crc_bruteforce->crc_model_match();
	bool match = false;
	for (size_t i = 0; i < results.size(); i++) {
		if (results[i].polynomial == model.polynomial &&
			results[i].initial == model.initial &&
			results[i].final_xor == model.final_xor &&
			results[i].reflected_output == model.reflected_output &&
			results[i].reflected_input == model.reflected_input)
			match = true;
	}

	// Check the correct model was one of those identified
	BOOST_CHECK(match == true);

}
#endif

#ifdef CRCSIXTEEN
BOOST_AUTO_TEST_CASE(crcSixteen)
{
	// 16 bit CRC's
	bf_crc *crc_bruteforce;
	uint16_t crc_width = 16;
	bf_crc::crc_t crc(crc_width);
	boost::dynamic_bitset<> msg;

	// Lets make sure things are random
	srand((unsigned)time(0));

	std::vector<bf_crc::test_vector_t> test_vectors;
	bf_crc::test_vector_t test_vector;

	/*
	 * CRC-16/CCITT-FALSE
	 * width=16 poly=0x1021 init=0xffff refin=false refout=false xorout=0x0000 check=0x29b1 name="CRC-16/CCITT-FALSE"
	 */

	// Model of the CRC to brute force
	bf_crc::crc_model_t model(0x1021, 0xFFFF, 0x0000, false, false);

	// REVENG Check
	uint8_t data_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}; 
	test_vector.crc = calculate_crc(crc_width, data_0, sizeof(data_0), model, (boost::dynamic_bitset<>*)&msg);
	test_vector.message = msg;
	test_vectors.push_back(test_vector);

	// Check the CRC engine is still working...
	BOOST_CHECK(test_vector.crc == 0x29B1);

	for (int i = 0; i < 10; i++) {

		uint8_t data[9];
		for (int b = 0; b < 9; b++)
			data[b] = getRandomChar();

		test_vector.crc = calculate_crc(crc_width, data, sizeof(data_0), model, (boost::dynamic_bitset<>*)&msg);
		test_vector.message = msg;
		test_vectors.push_back(test_vector);

	}

	crc_bruteforce = new bf_crc(crc_width, 	// CRC Width
								0, 			// Polynomial
								false, 		// Probe Final XOR?
								0, 			// Final XOR
								true,   	// Probe Initial?
								0, 			// Initial
								false, 		// Probe Reflected Input?
								false);		// Probe Reflected Output?
	crc_bruteforce->set_verbose(true);
	crc_bruteforce->do_brute_force(4, test_vectors);

	// Get results
	std::vector<bf_crc::crc_model_t> results = crc_bruteforce->crc_model_match();
	bool match = false;
	for (size_t i = 0; i < results.size(); i++) {
		if (results[i].polynomial == model.polynomial &&
			results[i].initial == model.initial &&
			results[i].final_xor == model.final_xor &&
			results[i].reflected_output == model.reflected_output &&
			results[i].reflected_input == model.reflected_input)
			match = true;
	}

	// Check the correct model was one of those identified
	BOOST_CHECK(match == true);

}
#endif

#ifdef CRCTHIRTYTWO
BOOST_AUTO_TEST_CASE(crcThirtyTwo)
{
	// 32 bit CRC's
	bf_crc *crc_bruteforce;
	uint16_t crc_width = 32;
	bf_crc::crc_t crc(crc_width);
	boost::dynamic_bitset<> msg;

	// Lets make sure things are random
	srand((unsigned)time(0));

	std::vector<bf_crc::test_vector_t> test_vectors;
	bf_crc::test_vector_t test_vector;

	/*
	 * CRC-32/BZIP2
	 * width=32 poly=0x04c11db7 init=0xffffffff refin=false refout=false xorout=0xffffffff check=0xfc891918 name="CRC-32/BZIP2"
	 */

	// Model of the CRC to be brute forced
	bf_crc::crc_model_t model(0x04c11db7, 0xffffffff, 0xffffffff, false, false);

	// REVENG Check
	uint8_t data_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
	test_vector.crc = calculate_crc(crc_width, data_0, sizeof(data_0), model, (boost::dynamic_bitset<>*)&msg); 
	test_vector.message = msg;
	test_vectors.push_back(test_vector);

	// Check the CRC engine worked
	BOOST_CHECK(test_vector.crc == 0xFC891918);

	// Make another 10 test vectors
	for (int i = 0; i < 10; i++) {

		// Create some random data
		uint8_t data[9];
		for (int b = 0; b < 9; b++)
			data[b] = getRandomChar();

		test_vector.crc = calculate_crc(crc_width, data, sizeof(data), model, (boost::dynamic_bitset<>*)&msg);
		test_vector.message = msg;
		test_vectors.push_back(test_vector);

	}

	crc_bruteforce = new bf_crc(crc_width, 	// CRC Width
								0, 			// Polynomial
								false, 		// Probe Final XOR?
								0xFFFFFFFF, // Final XOR
								false,   	// Probe Initial?
								0xFFFFFFFF, // Initial
								false, 		// Probe Reflected Input?
								false);		// Probe Reflected Output?
	crc_bruteforce->set_verbose(true);
	crc_bruteforce->set_polynomial_start(0x00000000);
	crc_bruteforce->set_polynomial_end(0x10000000);
	crc_bruteforce->do_brute_force(4, test_vectors);

	// Get results
	std::vector<bf_crc::crc_model_t> results = crc_bruteforce->crc_model_match();
	bool match = false;
	for (size_t i = 0; i < results.size(); i++) {
		if (results[i].polynomial == model.polynomial &&
			results[i].initial == model.initial &&
			results[i].final_xor == model.final_xor &&
			results[i].reflected_output == model.reflected_output &&
			results[i].reflected_input == model.reflected_input)
			match = true;
	}

	// Test to make sure the model was identified
	BOOST_CHECK(match == true);

}
#endif

