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

boost::dynamic_bitset<> convert_uint8_to_bitset(const uint8_t array[], size_t size) {

	boost::dynamic_bitset<> retVal(size*8);

	for (unsigned int i = 0; i < size; i++)
		for (int j = 0; j < 8; j++)
			retVal[i*8+j] = (array[i] >> (7-j)) & 0x1 ? true : false;

	return retVal;
}

boost::dynamic_bitset<> convert_string_to_bitset(std::string str)
{
	boost::dynamic_bitset<> retVal(str.length());

	for (size_t i = 0; i < str.length(); i++)
		retVal[i] = str[i] == '1' ? true : false;

	return retVal;
}

uint32_t calculate_crc(uint32_t width, const uint8_t* data, size_t length, uint32_t polynomial, uint32_t initial, uint32_t final_xor, bool reflected_input, bool reflected_output)
{
	crc_t crc(width);
	boost::dynamic_bitset<> msg = convert_uint8_to_bitset(data, length);

	crc.set(polynomial, initial, final_xor, reflected_input, reflected_output);
	crc.calc_crc(initial, msg);
	return crc.checksum();
}

uint32_t calculate_crc(uint32_t crc_width, std::string data, uint32_t polynomial, uint32_t initial, uint32_t final_xor, bool reflected_input, bool reflected_output)
{
	crc_t crc(crc_width);
	boost::dynamic_bitset<> msg = convert_string_to_bitset(data);

	crc.set(polynomial, initial, final_xor, reflected_input, reflected_output);
	crc.calc_crc(initial, msg);
	return crc.checksum();
}
	

BOOST_AUTO_TEST_CASE(crcFive)
{
	// 5 bit CRC's
	uint8_t crc_width = 5;
	crc_t crc(crc_width);
	uint32_t calculated_crc;

	/*
	 * CRC-5/EPC
	 * width=5 poly=0x09 init=0x09 refin=false refout=false xorout=0x00 check=0x00 name="CRC-5/EPC"
	 */

	// REVENG Test Check
	uint8_t data_1_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};
	calculated_crc = calculate_crc(crc_width, data_1_0, 9, 0x9, 0x9, 0x0, false, false);
	BOOST_CHECK(calculated_crc == 0x00);

	// High Security FeRAM-Based EPC C2G2 UHF (https://etrij.etri.re.kr/etrij/journal/getPublishedPaperFile.do?fileId=SPF-1228283393442)
	calculated_crc = calculate_crc(crc_width, "10001001000000100", 0x9, 0x9, 0x0, false, false);
	BOOST_CHECK(calculated_crc == 0x06);

	// Computer Interfacing Forum (topic 1330, non authoritiative)
	calculated_crc = calculate_crc(crc_width, "10000001000000000", 0x9, 0x9, 0x0, false, false);
	BOOST_CHECK(calculated_crc == 0x13);

	/*
	 * CRC-5/ITU
	 * width=5 poly=0x15 init=0x00 refin=true refout=true xorout=0x00 check=0x07 name="CRC-5/ITU"
	 */

	// REVENG Test Check
	uint8_t data_2_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}; 
	calculated_crc = calculate_crc(crc_width, data_2_0, 9, 0x15, 0x0, 0x0, true, true);
	BOOST_CHECK(calculated_crc == 0x07);

	/*
 	 * CRC-5/USB
	 * width=5 poly=0x05 init=0x1f refin=true refout=true xorout=0x1f check=0x19 name="CRC-5/USB"
	 */

	// REVENG Test Check
	uint8_t data_3_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}; 
	calculated_crc = calculate_crc(crc_width, data_3_0, 9, 0x05, 0x1F, 0x1F, true, true);
	BOOST_CHECK(calculated_crc == 0x019);

	// Darft Implementation 1 TODO: These test cases do not match the exemplar / description
	calculated_crc = calculate_crc(crc_width, "10101000111", 0x05, 0x1F, 0x1F, false, false);
	BOOST_CHECK(calculated_crc == 0x017);

	// Darft Implementation 2
	calculated_crc = calculate_crc(crc_width, "01011100101", 0x05, 0x1F, 0x1F, false, false);
	BOOST_CHECK(calculated_crc == 0x01C);

	// Darft Implementation 3
	calculated_crc = calculate_crc(crc_width, "00001110010", 0x05, 0x1F, 0x1F, false, false);
	BOOST_CHECK(calculated_crc == 0x00E);

	// Darft Implementation 4
	calculated_crc = calculate_crc(crc_width, "10000000000", 0x05, 0x1F, 0x1F, false, false);
	BOOST_CHECK(calculated_crc == 0x017);

}

BOOST_AUTO_TEST_CASE(crcFourteen)
{
	// 14 bit CRC's
	uint8_t crc_width = 14;
	uint32_t calculated_crc;

	crc_t crc(crc_width);

	/*
	 * CRC-14/DARC
	 * width=14 poly=0x0805 init=0x0000 refin=true refout=true xorout=0x0000 check=0x082d name="CRC-14/DARC"
	 */

	// REVENG Test Check
	uint8_t data_1_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}; 
	calculated_crc = calculate_crc(crc_width, data_1_0, 9, 0x805, 0x0, 0x0, true, true);
	BOOST_CHECK(calculated_crc == 0x82d);

	// ETSI EN 300 751 - TODO: Needs Verification
	uint8_t data_1_1[] = {0x02, 0x00, 0x01, 0x02, 0x37, 0x20, 0x50, 0x52, 0x4F, 0x4A, 0x45, 0x43, 0x54, 0x20, 0x4D, 0x41, 0x49, 0x4E, 0x4D, 0x45, 0x4E, 0x55}; 
	calculated_crc = calculate_crc(crc_width, data_1_1, sizeof(data_1_1), 0x805, 0x0, 0x0, true, true);
	BOOST_CHECK(calculated_crc == 0x83B);

}


BOOST_AUTO_TEST_CASE(crcSixteen)
{
	// 16 bit CRC's
	uint8_t crc_width = 16;
	uint32_t calculated_crc;

	crc_t crc(crc_width);

	/*
	 * ARC
	 * width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000 check=0xbb3d name="ARC"
	 */

	// REVENG Test Check
	uint8_t data_1_0[] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39};  
	calculated_crc = calculate_crc(crc_width, data_1_0, sizeof(data_1_0), 0x8005, 0x0, 0x0, true, true);
	BOOST_CHECK(calculated_crc == 0xBB3D);

	/* 
	 * CRC-16/CCITT-FALSE
	 * width=16 poly=0x1021 init=0xffff refin=false refout=false xorout=0x0000 check=0x29b1 name="CRC-16/CCITT-FALSE"
	 */

	// Autosar Release 4.2.2 p.25 : 00 00 00 00 : 84C0
	uint8_t data_3_0[] = {0x00, 0x00, 0x00, 0x00};  
	calculated_crc = calculate_crc(crc_width, data_3_0, sizeof(data_3_0), 0x1021, 0xFFFF, 0x0, false, false);
	BOOST_CHECK(calculated_crc == 0x84C0);

	// Autosar Release 4.2.2 p.25 : F2 01 83 : D374
	uint8_t data_3_1[] = {0xF2, 0x01, 0x83};  
	calculated_crc = calculate_crc(crc_width, data_3_1, sizeof(data_3_1), 0x1021, 0xFFFF, 0x0, false, false);
	BOOST_CHECK(calculated_crc == 0xD374);

	// Autosar Release 4.2.2 p.25 : 0F AA 00 55 : 2023
	uint8_t data_3_2[] = {0x0F, 0xAA, 0x00, 0x55};  
	calculated_crc = calculate_crc(crc_width, data_3_2, sizeof(data_3_2), 0x1021, 0xFFFF, 0x0, false, false);
	BOOST_CHECK(calculated_crc == 0x2023);

	// Autosar Release 4.2.2 p.25 : 00 FF 55 11 : B8F9
	uint8_t data_3_3[] = {0x00, 0xFF, 0x55, 0x11};  
	calculated_crc = calculate_crc(crc_width, data_3_3, sizeof(data_3_3), 0x1021, 0xFFFF, 0x0, false, false);
	BOOST_CHECK(calculated_crc == 0xB8F9);

	// Autosar Release 4.2.2 p.25 : 33 22 55 AA BB CC DD EE FF : F53F
	uint8_t data_3_4[] = {0x33, 0x22, 0x55, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};  
	calculated_crc = calculate_crc(crc_width, data_3_4, sizeof(data_3_4), 0x1021, 0xFFFF, 0x0, false, false);
	BOOST_CHECK(calculated_crc == 0xF53F);

	// Autosar Release 4.2.2 p.25 : 92 6B 55 : 0745
	uint8_t data_3_5[] = {0x92, 0x6B, 0x55}; 
	calculated_crc = calculate_crc(crc_width, data_3_5, sizeof(data_3_5), 0x1021, 0xFFFF, 0x0, false, false);
	BOOST_CHECK(calculated_crc == 0x0745); 

	// Autosar Release 4.2.2 p.25 : FF FF FF FF : 1D0F
	uint8_t data_3_6[] = {0xFF, 0xFF, 0xFF, 0xFF};  
	calculated_crc = calculate_crc(crc_width, data_3_6, sizeof(data_3_6), 0x1021, 0xFFFF, 0x0, false, false);
	BOOST_CHECK(calculated_crc == 0x1D0F);

}


