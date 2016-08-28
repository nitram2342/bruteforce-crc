//
// Test vectors generated from the crc-catalogue:
// http://reveng.sourceforge.net/crc-catalogue/
//

#include <boost/dynamic_bitset.hpp>
/*#include <boost/program_options.hpp>
#include <boost/foreach.hpp>
#include <boost/regex.hpp>
#include <boost/integer.hpp>
#include <boost/thread.hpp>
#include <boost/format.hpp>
*/

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE "Test the CRC engine"
#include <boost/test/unit_test.hpp>

#include "../crc.hpp"

typedef my_crc_basic crc_t;

boost::dynamic_bitset<> convert_to_bitset(uint8_t array[], size_t size) {

	boost::dynamic_bitset<> retVal(size*8);

	for (unsigned int i = 0; i < size; i++)
		for (int j = 0; j < 8; j++)
			retVal[i*8+j] = (array[i] >> (7-j)) & 0x1 ? true : false;

	return retVal;
}


BOOST_AUTO_TEST_CASE(crcFourteen)
{
	// 14 bit CRC's
	typedef boost::dynamic_bitset<> dbType;
	crc_t crc(14);
	dbType msg;

	/*
	 * CRC-14/DARC
	 * width=14 poly=0x0805 init=0x0000 refin=true refout=true xorout=0x0000 check=0x082d name="CRC-14/DARC"
	 */

	// REVENG Test Check
	uint8_t data_1_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}; 
	msg = convert_to_bitset(data_1_0, 9);
	crc.set(0x0805, // Poly
			0x0000, // Initial (Overwritten)
			0x0000, // Final XOR
			true,  // Reflect input
			true); // Reflect output
	BOOST_CHECK(crc.calc_crc(	0x0000, 			// Initial
			    				msg,				// Data
			    				0,					// Start offset
			    				sizeof(data_1_0)*8,	// End data (# of bits)
			    				0x082d) == 1);		// Expected CRC

	// ETSI EN 300 751 - TODO: Needs Verification
	uint8_t data_1_1[] = {0x02, 0x00, 0x01, 0x02, 0x37, 0x20, 0x50, 0x52, 0x4F, 0x4A, 0x45, 0x43, 0x54, 0x20, 0x4D, 0x41, 0x49, 0x4E, 0x4D, 0x45, 0x4E, 0x55}; 
	msg = convert_to_bitset(data_1_1, 22);
	crc.set(0x0805, // Poly
			0x0000, // Initial (Overwritten)
			0x0000, // Final XOR
			true,  // Reflect input
			true); // Reflect output
	BOOST_CHECK(crc.calc_crc(	0x0000, 			// Initial
			    				msg,				// Data
			    				0,					// Start offset
			    				sizeof(data_1_1)*8,	// End data (# of bits)
			    				0x083B) == 1);		// Expected CRC

}

BOOST_AUTO_TEST_CASE(crcSixteen)
{
	// 16 bit CRC's
	typedef boost::dynamic_bitset<> dbType;
	crc_t crc(16);
	dbType msg;

	/*
	 * ARC
	 * width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000 check=0xbb3d name="ARC"
	 */

	// REVENG Test Check
	uint8_t data_1_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}; 
	msg = convert_to_bitset(data_1_0, 9);
	crc.set(0x8005, // Poly
			0x0000, // Initial (Overwritten)
			0x0000, // Final XOR
			true,  // Reflect input
			true); // Reflect output
	BOOST_CHECK(crc.calc_crc(	0x0000, 			// Initial
			    				msg,				// Data
			    				0,					// Start offset
			    				sizeof(data_1_0)*8,	// End data (# of bits)
			    				0xBB3D) == 1);		// Expected CRC

	/* 
	 * CRC-16/CCITT-FALSE
	 * width=16 poly=0x1021 init=0xffff refin=false refout=false xorout=0x0000 check=0x29b1 name="CRC-16/CCITT-FALSE"
	 */

	// Autosar Release 4.2.2 p.25 : 00 00 00 00 : 84C0
	uint8_t data_3_0[] = {0x00, 0x00, 0x00, 0x00}; 
	msg = convert_to_bitset(data_3_0, 4);
	crc.set(0x1021, // Poly
			0xffff, // Initial (Overwritten)
			0x0000, // Final XOR
			false,  // Reflect input
			false); // Reflect output
	BOOST_CHECK(crc.calc_crc(	0xFFFF, 			// Initial
			    				msg,				// Data
			    				0,					// Start offset
			    				sizeof(data_3_0)*8,	// End data (# of bits)
			    				0x84C0) == 1);		// Expected CRC

	// Autosar Release 4.2.2 p.25 : F2 01 83 : D374
	uint8_t data_3_1[] = {0xF2, 0x01, 0x83}; 
	msg = convert_to_bitset(data_3_1, 3);
	crc.set(0x1021, // Poly
			0xffff, // Initial (Overwritten)
			0x0000, // Final XOR
			false,  // Reflect input
			false); // Reflect output
	BOOST_CHECK(crc.calc_crc(	0xFFFF, 			// Initial
			    				msg,				// Data
			    				0,					// Start offset
			    				sizeof(data_3_1)*8,	// End data (# of bits)
			    				0xD374) == 1);		// Expected CRC

	// Autosar Release 4.2.2 p.25 : 0F AA 00 55 : 2023
	uint8_t data_3_2[] = {0x0F, 0xAA, 0x00, 0x55}; 
	msg = convert_to_bitset(data_3_2, 4);
	crc.set(0x1021, // Poly
			0xffff, // Initial (Overwritten)
			0x0000, // Final XOR
			false,  // Reflect input
			false); // Reflect output
	BOOST_CHECK(crc.calc_crc(	0xFFFF, 			// Initial
			    				msg,				// Data
			    				0,					// Start offset
			    				sizeof(data_3_2)*8,	// End data (# of bits)
			    				0x2023) == 1);		// Expected CRC

	// Autosar Release 4.2.2 p.25 : 00 FF 55 11 : B8F9
	uint8_t data_3_3[] = {0x00, 0xFF, 0x55, 0x11}; 
	msg = convert_to_bitset(data_3_3, 4);
	crc.set(0x1021, // Poly
			0xffff, // Initial (Overwritten)
			0x0000, // Final XOR
			false,  // Reflect input
			false); // Reflect output
	BOOST_CHECK(crc.calc_crc(	0xFFFF, 			// Initial
			    				msg,				// Data
			    				0,					// Start offset
			    				sizeof(data_3_3)*8,	// End data (# of bits)
			    				0xB8F9) == 1);		// Expected CRC


	// Autosar Release 4.2.2 p.25 : 33 22 55 AA BB CC DD EE FF : F53F
	uint8_t data_3_4[] = {0x33, 0x22, 0x55, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}; 
	msg = convert_to_bitset(data_3_4, 9);
	crc.set(0x1021, // Poly
			0xffff, // Initial (Overwritten)
			0x0000, // Final XOR
			false,  // Reflect input
			false); // Reflect output
	BOOST_CHECK(crc.calc_crc(	0xFFFF, 			// Initial
			    				msg,				// Data
			    				0,					// Start offset
			    				sizeof(data_3_4)*8,	// End data (# of bits)
			    				0xF53F) == 1);		// Expected CRC
/* TODO:
92
6B
55
0745
FF
FF
FF
FF
1D0F*/
}


