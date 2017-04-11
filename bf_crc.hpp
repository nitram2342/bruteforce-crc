/*
 * Brute-force CRC based on known good vectors
 *
 * Original Author: Martin Schobert <schobert@sitsec.net>
 * Modified by MarytnP <git@disputedip.com>
 *
 *    Copyright Martin Schobert and MartynP 2012 - 2016.
 * Distributed under the Boost Software License, Version 1.0.
 *    (See accompanying file LICENSE_1_0.txt or copy at
 *          http://www.boost.org/LICENSE_1_0.txt)
 *
 */

#ifndef _BRUTEFORCE_CRC_LIB_HPP_
#define _BRUTEFORCE_CRC_LIB_HPP_

#include <list>
#include <sys/time.h>
#include <boost/thread.hpp>
#include <boost/dynamic_bitset.hpp>
#include "crc.hpp"

class bf_crc {

	public:

		typedef struct vector_ {
			boost::dynamic_bitset<> message;
			uint32_t crc;
		} test_vector_t;

		typedef class crc_model_ {
			public:
			uint32_t polynomial;
			uint32_t initial;
			uint32_t final_xor;
			bool reflected_input;
			bool reflected_output;
		  my_crc_basic::FEED_TYPE feed_type;

			crc_model_();
		  crc_model_(uint32_t polynomial, uint32_t initial, uint32_t final_xor, bool reflected_input, bool reflected_output, my_crc_basic::FEED_TYPE feed_type) :
				polynomial(polynomial), 
				initial(initial), 
				final_xor(final_xor), 
				reflected_input(reflected_input), 
				reflected_output(reflected_output),
				feed_type(feed_type)
				
			{}
			bool compare(const crc_model_& crc_model) const {
				if (crc_model.polynomial != polynomial ||
					crc_model.initial != initial ||
					crc_model.final_xor != final_xor ||
					crc_model.reflected_input != reflected_input ||
				    crc_model.reflected_output != reflected_output)
				  // skip feed type in comparison
				  
					return 0;
				else
					return 1;
			}
			bool operator == (const crc_model_& d) const {
				return compare(d);
			}
			
		} crc_model_t;

		typedef my_crc_basic crc_t;

		bf_crc(	uint16_t crc_width, 
				uint32_t polynomial, 
				bool probe_final_xor, 
				uint32_t final_xor, 
				bool probe_initial, 
				uint32_t initial, 
				bool probe_reflected_input, 
			bool probe_reflected_output,
			my_crc_basic::FEED_TYPE feed_type) {
			set_parameters(	crc_width, 
							polynomial, 
							probe_final_xor, 
							final_xor, 
							probe_initial, 
							initial, 
							probe_reflected_input, 
					probe_reflected_output, feed_type);
			crc_model_match_.clear();
			verbose_ = false;
			quiet_ = false;
			reflected_input_ = false;
			reflected_output_ = false;


			// Polulate known models from http://reveng.sourceforge.net
			std::vector<crc_model_t> crc_0;
			known_models.push_back(crc_0);

			std::vector<crc_model_t> crc_1;
			known_models.push_back(crc_1);

			std::vector<crc_model_t> crc_2;
			known_models.push_back(crc_2);

			std::vector<crc_model_t> crc_3;
			{
				// width=3 poly=0x3 init=0x7 refin=true refout=true xorout=0x0 check=0x6 name="CRC-3/ROHC"
			  crc_3.push_back(crc_model_t(0x3, 0x7, 0x0, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_3);

			std::vector<crc_model_t> crc_4;
			{
				// width=4 poly=0x3 init=0xf refin=false refout=false xorout=0xf check=0xb name="CRC-4/INTERLAKEN"
				crc_4.push_back(crc_model_t(0x3, 0xf, 0xf, false, false, my_crc_basic::AUTO));
				// width=4 poly=0x3 init=0x0 refin=true refout=true xorout=0x0 check=0x7 name="CRC-4/ITU"
				crc_4.push_back(crc_model_t(0x3, 0x0, 0x0, true, true, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_4);

			std::vector<crc_model_t> crc_5;
			{
				// width=5 poly=0x09 init=0x09 refin=false refout=false xorout=0x00 check=0x00 name="CRC-5/EPC"
				crc_5.push_back(crc_model_t(0x09, 0x9, 0x0, false, false, my_crc_basic::AUTO));
				// width=5 poly=0x15 init=0x00 refin=true refout=true xorout=0x00 check=0x07 name="CRC-5/ITU"
				crc_5.push_back(crc_model_t(0x15, 0x1f, 0x1f, true, true, my_crc_basic::AUTO));
				// width=5 poly=0x05 init=0x1f refin=true refout=true xorout=0x1f check=0x19 name="CRC-5/USB"
				crc_5.push_back(crc_model_t(0x05, 0x1f, 0x1f, true, true, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_5);

			std::vector<crc_model_t> crc_6;
			{
				// width=6 poly=0x27 init=0x3f refin=false refout=false xorout=0x00 check=0x0d name="CRC-6/CDMA2000-A"
				crc_6.push_back(crc_model_t(0x27, 0x3f, 0x00, false, false, my_crc_basic::AUTO));
				// width=6 poly=0x07 init=0x3f refin=false refout=false xorout=0x00 check=0x3b name="CRC-6/CDMA2000-B"
				crc_6.push_back(crc_model_t(0x02, 0x3f, 0x00, false, false, my_crc_basic::AUTO));
				// width=6 poly=0x19 init=0x00 refin=true refout=true xorout=0x00 check=0x26 name="CRC-6/DARC"
				crc_6.push_back(crc_model_t(0x19, 0x00, 0x00, true, true, my_crc_basic::AUTO));
				// width=6 poly=0x03 init=0x00 refin=true refout=true xorout=0x00 check=0x06 name="CRC-6/ITU"
				crc_6.push_back(crc_model_t(0x03, 0x00, 0x00, true, true, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_6);

			std::vector<crc_model_t> crc_7;
			{
				// width=7 poly=0x09 init=0x00 refin=false refout=false xorout=0x00 check=0x75 name="CRC-7"
				crc_7.push_back(crc_model_t(0x09, 0x00, 0x00, false, false, my_crc_basic::AUTO));
				// width=7 poly=0x4f init=0x7f refin=true refout=true xorout=0x00 check=0x53 name="CRC-7/ROHC"
				crc_7.push_back(crc_model_t(0x4f, 0x7f, 0x00, true, true, my_crc_basic::AUTO));
				// width=7 poly=0x45 init=0x00 refin=false refout=false xorout=0x00 check=0x61 name="CRC-7/UMTS"
				crc_7.push_back(crc_model_t(0x45, 0x00, 0x00, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_7);

			std::vector<crc_model_t> crc_8;
			{
				// width=8 poly=0x07 init=0x00 refin=false refout=false xorout=0x00 check=0xf4 name="CRC-8"
				crc_8.push_back(crc_model_t(0x07, 0x00, 0x00, false, false, my_crc_basic::AUTO));
				// width=8 poly=0x2f init=0xff refin=false refout=false xorout=0xff check=0xdf name="CRC-8/AUTOSAR"
				crc_8.push_back(crc_model_t(0x2f, 0xff, 0xff, false, false, my_crc_basic::AUTO));
				// width=8 poly=0x9b init=0xff refin=false refout=false xorout=0x00 check=0xda name="CRC-8/CDMA2000"
				crc_8.push_back(crc_model_t(0x9b, 0xff, 0x00, false, false, my_crc_basic::AUTO));
				// width=8 poly=0x39 init=0x00 refin=true refout=true xorout=0x00 check=0x15 name="CRC-8/DARC"
				crc_8.push_back(crc_model_t(0x39, 0x00, 0x00, true, true, my_crc_basic::AUTO));
				// width=8 poly=0xd5 init=0x00 refin=false refout=false xorout=0x00 check=0xbc name="CRC-8/DVB-S2"
				crc_8.push_back(crc_model_t(0xd5, 0x00, 0x00, false, false, my_crc_basic::AUTO));
				// width=8 poly=0x1d init=0xff refin=true refout=true xorout=0x00 check=0x97 name="CRC-8/EBU"
				crc_8.push_back(crc_model_t(0x1d, 0xff, 0x00, true, true, my_crc_basic::AUTO));
				// width=8 poly=0x1d init=0xfd refin=false refout=false xorout=0x00 check=0x7e name="CRC-8/I-CODE"
				crc_8.push_back(crc_model_t(0x1d, 0xfd, 0x00, false, false, my_crc_basic::AUTO));
				// width=8 poly=0x07 init=0x00 refin=false refout=false xorout=0x55 check=0xa1 name="CRC-8/ITU"
				crc_8.push_back(crc_model_t(0x07, 0x00, 0xff, false, false, my_crc_basic::AUTO));
				// width=8 poly=0x9b init=0x00 refin=false refout=false xorout=0x00 check=0xea name="CRC-8/LTE"
				crc_8.push_back(crc_model_t(0x9b, 0x00, 0x00, false, false, my_crc_basic::AUTO));
				// width=8 poly=0x31 init=0x00 refin=true refout=true xorout=0x00 check=0xa1 name="CRC-8/MAXIM"
				crc_8.push_back(crc_model_t(0x31, 0x00, 0x00, true, true, my_crc_basic::AUTO));
				// width=8 poly=0x2f init=0x00 refin=false refout=false xorout=0x00 check=0x3e name="CRC-8/OPENSAFETY"
				crc_8.push_back(crc_model_t(0x2f, 0x00, 0x00, false, false, my_crc_basic::AUTO));
				// width=8 poly=0x07 init=0xff refin=true refout=true xorout=0x00 check=0xd0 name="CRC-8/ROHC"
				crc_8.push_back(crc_model_t(0x07, 0xff, 0x00, true, true, my_crc_basic::AUTO));
				// width=8 poly=0x1d init=0xff refin=false refout=false xorout=0xff check=0x4b name="CRC-8/SAE-J1850"
				crc_8.push_back(crc_model_t(0x1d, 0xff, 0xff, false, false, my_crc_basic::AUTO));
				// width=8 poly=0x9b init=0x00 refin=true refout=true xorout=0x00 check=0x25 name="CRC-8/WCDMA"
				crc_8.push_back(crc_model_t(0x9b, 0x00, 0x00, true, true, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_8);

			std::vector<crc_model_t> crc_9;
			known_models.push_back(crc_9);

			std::vector<crc_model_t> crc_10;
			{	
				// width=10 poly=0x233 init=0x000 refin=false refout=false xorout=0x000 check=0x199 name="CRC-10"
				crc_10.push_back(crc_model_t(0x233, 0x000, 0x000, false, false, my_crc_basic::AUTO));
				// width=10 poly=0x3d9 init=0x3ff refin=false refout=false xorout=0x000 check=0x233 name="CRC-10/CDMA2000"
				crc_10.push_back(crc_model_t(0x3d9, 0x3ff, 0x000, false, false, my_crc_basic::AUTO));
				crc_10.push_back(crc_model_t(0x0bd, 0x00, 0x00, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_10);

			std::vector<crc_model_t> crc_11;
			{
				// width=11 poly=0x385 init=0x01a refin=false refout=false xorout=0x000 check=0x5a3 name="CRC-11"
				crc_11.push_back(crc_model_t(0x385, 0x01a, 0x000, false, false, my_crc_basic::AUTO));
				// width=11 poly=0x307 init=0x000 refin=false refout=false xorout=0x000 check=0x061 name="CRC-11/UMTS"
				crc_11.push_back(crc_model_t(0x307, 0x000, 0x000, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_11);

			std::vector<crc_model_t> crc_12;
			{
				// width=12 poly=0xf13 init=0xfff refin=false refout=false xorout=0x000 check=0xd4d name="CRC-12/CDMA2000"
				crc_12.push_back(crc_model_t(0xf13, 0xfff, 0x000, false, false, my_crc_basic::AUTO));
				// width=12 poly=0x80f init=0x000 refin=false refout=false xorout=0x000 check=0xf5b name="CRC-12/DECT"
				crc_12.push_back(crc_model_t(0x80f, 0x000, 0x000, false ,false, my_crc_basic::AUTO));
				// width=12 poly=0x80f init=0x000 refin=false refout=true xorout=0x000 check=0xdaf name="CRC-12/UMTS"
				crc_12.push_back(crc_model_t(0x80f, 0x000, 0x000, false, true, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_12);

			std::vector<crc_model_t> crc_13;
			{
				// width=13 poly=0x1cf5 init=0x0000 refin=false refout=false xorout=0x0000 check=0x04fa name="CRC-13/BBC"
				crc_13.push_back(crc_model_t(0x1cf5, 0x0000, 0x0000, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_13);

			std::vector<crc_model_t> crc_14;
			{
				// width=14 poly=0x0805 init=0x0000 refin=true refout=true xorout=0x0000 check=0x082d name="CRC-14/DARC"
				crc_14.push_back(crc_model_t(0x0805, 0x0000, 0x0000, true, true, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_14);

			std::vector<crc_model_t> crc_15;
			{
				// width=15 poly=0x4599 init=0x0000 refin=false refout=false xorout=0x0000 check=0x059e name="CRC-15"
				crc_15.push_back(crc_model_t(0x4599, 0x0000, 0x0000, false, false, my_crc_basic::AUTO));
				// width=15 poly=0x6815 init=0x0000 refin=false refout=false xorout=0x0001 check=0x2566 name="CRC-15/MPT1327"
				crc_15.push_back(crc_model_t(0x6815, 0x0000, 0x0001, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_15);

			std::vector<crc_model_t> crc_16;
			{
				//width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0x0000 check=0xbb3d name="ARC"
				crc_16.push_back(crc_model_t(0x8005, 0x0000, 0x0000, true, true, my_crc_basic::AUTO));
				//width=16 poly=0x1021 init=0x1d0f refin=false refout=false xorout=0x0000 check=0xe5cc name="CRC-16/AUG-CCITT"
				crc_16.push_back(crc_model_t(0x1021, 0x1d0f, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x8005 init=0x0000 refin=false refout=false xorout=0x0000 check=0xfee8 name="CRC-16/BUYPASS"
				crc_16.push_back(crc_model_t(0x8005, 0x0000, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x1021 init=0xffff refin=false refout=false xorout=0x0000 check=0x29b1 name="CRC-16/CCITT-FALSE"
				crc_16.push_back(crc_model_t(0x1021, 0xffff, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0xc867 init=0xffff refin=false refout=false xorout=0x0000 check=0x4c06 name="CRC-16/CDMA2000"
				crc_16.push_back(crc_model_t(0xc867, 0xffff, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x8005 init=0xffff refin=false refout=false xorout=0x0000 check=0xaee7 name="CRC-16/CMS"
				crc_16.push_back(crc_model_t(0x8005, 0xffff, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x8005 init=0x800d refin=false refout=false xorout=0x0000 check=0x9ecf name="CRC-16/DDS-110"
				crc_16.push_back(crc_model_t(0x8005, 0x800d, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x0589 init=0x0000 refin=false refout=false xorout=0x0001 check=0x007e name="CRC-16/DECT-R"
				crc_16.push_back(crc_model_t(0x0589, 0x0000, 0x0001, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x0589 init=0x0000 refin=false refout=false xorout=0x0000 check=0x007f name="CRC-16/DECT-X"
				crc_16.push_back(crc_model_t(0x0589, 0x0000, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x3d65 init=0x0000 refin=true refout=true xorout=0xffff check=0xea82 name="CRC-16/DNP"
				crc_16.push_back(crc_model_t(0x3d65, 0x0000, 0xffff, true, true, my_crc_basic::AUTO));
				//width=16 poly=0x3d65 init=0x0000 refin=false refout=false xorout=0xffff check=0xc2b7 name="CRC-16/EN-13757"
				crc_16.push_back(crc_model_t(0x3d65, 0x0000, 0xffff, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x1021 init=0xffff refin=false refout=false xorout=0xffff check=0xd64e name="CRC-16/GENIBUS"
				crc_16.push_back(crc_model_t(0x1021, 0xffff, 0xffff, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x6f63 init=0x0000 refin=false refout=false xorout=0x0000 check=0xbdf4 name="CRC-16/LJ1200"
				crc_16.push_back(crc_model_t(0x6f63, 0x0000, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x8005 init=0x0000 refin=true refout=true xorout=0xffff check=0x44c2 name="CRC-16/MAXIM"
				crc_16.push_back(crc_model_t(0x8005, 0x0000, 0xffff, true, true, my_crc_basic::AUTO));
				//width=16 poly=0x1021 init=0xffff refin=true refout=true xorout=0x0000 check=0x6f91 name="CRC-16/MCRF4XX"
				crc_16.push_back(crc_model_t(0x1021, 0xffff, 0x0000, true, true, my_crc_basic::AUTO));
				//width=16 poly=0x5935 init=0x0000 refin=false refout=false xorout=0x0000 check=0x5d38 name="CRC-16/OPENSAFETY-A"
				crc_16.push_back(crc_model_t(0x5935, 0x0000, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x755b init=0x0000 refin=false refout=false xorout=0x0000 check=0x20fe name="CRC-16/OPENSAFETY-B"
				crc_16.push_back(crc_model_t(0x755b, 0x0000, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x1dcf init=0xffff refin=false refout=false xorout=0xffff check=0xa819 name="CRC-16/PROFIBUS"
				crc_16.push_back(crc_model_t(0x1dcf, 0xffff, 0xffff, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x1021 init=0xb2aa refin=true refout=true xorout=0x0000 check=0x63d0 name="CRC-16/RIELLO"
				crc_16.push_back(crc_model_t(0x1021, 0xb2aa, 0x0000, true, true, my_crc_basic::AUTO));
				///width=16 poly=0x8bb7 init=0x0000 refin=false refout=false xorout=0x0000 check=0xd0db name="CRC-16/T10-DIF"
				crc_16.push_back(crc_model_t(0x8bb7, 0x0000, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0xa097 init=0x0000 refin=false refout=false xorout=0x0000 check=0x0fb3 name="CRC-16/TELEDISK"
				crc_16.push_back(crc_model_t(0xa097, 0x0000, 0x0000, false, false, my_crc_basic::AUTO));
				//width=16 poly=0x1021 init=0x89ec refin=true refout=true xorout=0x0000 check=0x26b1 name="CRC-16/TMS37157"
				crc_16.push_back(crc_model_t(0x1021, 0x89ec, 0x0000, true, true, my_crc_basic::AUTO));
				//width=16 poly=0x8005 init=0xffff refin=true refout=true xorout=0xffff check=0xb4c8 name="CRC-16/USB"
				crc_16.push_back(crc_model_t(0x8005, 0xffff, 0xffff, true, true, my_crc_basic::AUTO));
				//width=16 poly=0x1021 init=0xc6c6 refin=true refout=true xorout=0x0000 check=0xbf05 name="CRC-A"
				crc_16.push_back(crc_model_t(0x1021, 0xc6c6, 0x0000, true, true, my_crc_basic::AUTO));
				//width=16 poly=0x1021 init=0x0000 refin=true refout=true xorout=0x0000 check=0x2189 name="KERMIT"
				crc_16.push_back(crc_model_t(0x1021, 0x0000, 0x0000, true, true, my_crc_basic::AUTO));
				//width=16 poly=0x8005 init=0xffff refin=true refout=true xorout=0x0000 check=0x4b37 name="MODBUS"
				crc_16.push_back(crc_model_t(0x8005, 0xffff, 0x0000, true, true, my_crc_basic::AUTO));
				//width=16 poly=0x1021 init=0xffff refin=true refout=true xorout=0xffff check=0x906e name="X-25"
				crc_16.push_back(crc_model_t(0x1021, 0xffff, 0xffff, true, true, my_crc_basic::AUTO));
				//width=16 poly=0x1021 init=0x0000 refin=false refout=false xorout=0x0000 check=0x31c3 name="XMODEM"	
				crc_16.push_back(crc_model_t(0x1021, 0x0000, 0x0000, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_16);

			std::vector<crc_model_t> crc_17;
			known_models.push_back(crc_17);
	
			std::vector<crc_model_t> crc_18;
			known_models.push_back(crc_18);

			std::vector<crc_model_t> crc_19;
			known_models.push_back(crc_19);

			std::vector<crc_model_t> crc_20;
			known_models.push_back(crc_20);

			std::vector<crc_model_t> crc_21;
			known_models.push_back(crc_21);

			std::vector<crc_model_t> crc_22;
			known_models.push_back(crc_22);

			std::vector<crc_model_t> crc_23;
			known_models.push_back(crc_23);

			std::vector<crc_model_t> crc_24;
			{
				// width=24 poly=0x864cfb init=0xb704ce refin=false refout=false xorout=0x000000 check=0x21cf02 name="CRC-24"
				crc_24.push_back(crc_model_t(0x864cfb, 0xb704ce, 0x000000, false, false, my_crc_basic::AUTO));
				// width=24 poly=0x00065b init=0x555555 refin=true refout=true xorout=0x000000 check=0xc25a56 name="CRC-24/BLE"
				crc_24.push_back(crc_model_t(0x00065b, 0xffffff, 0x000000, true, true, my_crc_basic::AUTO));
				// width=24 poly=0x5d6dcb init=0xfedcba refin=false refout=false xorout=0x000000 check=0x7979bd name="CRC-24/FLEXRAY-A"
				crc_24.push_back(crc_model_t(0x5d6dcb, 0xfedcba, 0x000000, false, false, my_crc_basic::AUTO));
				// width=24 poly=0x5d6dcb init=0xabcdef refin=false refout=false xorout=0x000000 check=0x1f23b8 name="CRC-24/FLEXRAY-B"
				crc_24.push_back(crc_model_t(0x5d6dcb, 0xabcdef, 0x000000, false, false, my_crc_basic::AUTO));
				// width=24 poly=0x328b63 init=0xffffff refin=false refout=false xorout=0xffffff check=0xb4f3e6 name="CRC-24/INTERLAKEN"
				crc_24.push_back(crc_model_t(0x328b63, 0xffffff, 0xffffff, false, false, my_crc_basic::AUTO));
				// width=24 poly=0x864cfb init=0x000000 refin=false refout=false xorout=0x000000 check=0xcde703 name="CRC-24/LTE-A"
				crc_24.push_back(crc_model_t(0x864cfb, 0x000000, 0x000000, false, false, my_crc_basic::AUTO));
				// width=24 poly=0x800063 init=0x000000 refin=false refout=false xorout=0x000000 check=0x23ef52 name="CRC-24/LTE-B"
				crc_24.push_back(crc_model_t(0x800064, 0x000000, 0x000000, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_24);

			std::vector<crc_model_t> crc_25;
			known_models.push_back(crc_25);

			std::vector<crc_model_t> crc_26;
			known_models.push_back(crc_26);

			std::vector<crc_model_t> crc_27;
			known_models.push_back(crc_27);

			std::vector<crc_model_t> crc_28;
			known_models.push_back(crc_28);

			std::vector<crc_model_t> crc_29;
			known_models.push_back(crc_29);


			std::vector<crc_model_t> crc_30;
			{
				// width=30 poly=0x2030b9c7 init=0x3fffffff refin=false refout=false xorout=0x3fffffff check=0x04c34abf name="CRC-30/CDMA"
				crc_30.push_back(crc_model_t(0x2030b8c7, 0x3fffffff, 0x3fffffff, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_30);

			std::vector<crc_model_t> crc_31;
			{
				// width=31 poly=0x04c11db7 init=0x7fffffff refin=false refout=false xorout=0x7fffffff check=0x0ce9e46c name="CRC-31/PHILIPS"
				crc_31.push_back(crc_model_t(0x04c11db7, 0x7fffffff, 0x7fffffff, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_31);

			std::vector<crc_model_t> crc_32;
			{
				// width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xcbf43926 name="CRC-32"
				crc_32.push_back(crc_model_t(0x04c11db7, 0xffffffff, 0xffffffff, true, true, my_crc_basic::AUTO));
				// width=32 poly=0xf4acfb13 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0x1697d06a name="CRC-32/AUTOSAR"
				crc_32.push_back(crc_model_t(0xf4acfb13, 0xffffffff, 0xffffffff, true, true, my_crc_basic::AUTO));
				// width=32 poly=0x04c11db7 init=0xffffffff refin=false refout=false xorout=0xffffffff check=0xfc891918 name="CRC-32/BZIP2"
				crc_32.push_back(crc_model_t(0x04c11db7, 0xffffffff, 0xffffffff, false, false, my_crc_basic::AUTO));
				// width=32 poly=0x1edc6f41 init=0xffffffff refin=true refout=true xorout=0xffffffff check=0xe3069283 name="CRC-32C"
				crc_32.push_back(crc_model_t(0x1edc6f31, 0xffffffff, 0xffffffff, true, true, my_crc_basic::AUTO));
				// width=32 poly=0xa833982b init=0xffffffff refin=true refout=true xorout=0xffffffff check=0x87315576 name="CRC-32D"
				crc_32.push_back(crc_model_t(0xa833982b, 0xffffffff, 0xffffffff, true, true, my_crc_basic::AUTO));
				// width=32 poly=0x04c11db7 init=0xffffffff refin=false refout=false xorout=0x00000000 check=0x0376e6e7 name="CRC-32/MPEG-2"
				crc_32.push_back(crc_model_t(0x04c11db7, 0xffffffff, 0x00000000, false, false, my_crc_basic::AUTO));
				// width=32 poly=0x04c11db7 init=0x00000000 refin=false refout=false xorout=0xffffffff check=0x765e7680 name="CRC-32/POSIX"
				crc_32.push_back(crc_model_t(0x04c11db7, 0x00000000, 0xffffffff, false, false, my_crc_basic::AUTO));
				// width=32 poly=0x814141ab init=0x00000000 refin=false refout=false xorout=0x00000000 check=0x3010bf7f name="CRC-32Q"
				crc_32.push_back(crc_model_t(0x814141ab, 0x00000000, 0x00000000, false, false, my_crc_basic::AUTO));
				// width=32 poly=0x04c11db7 init=0xffffffff refin=true refout=true xorout=0x00000000 check=0x340bc6d9 name="JAMCRC"
				crc_32.push_back(crc_model_t(0x04c11db7, 0xffffffff, 0x00000000, true, true, my_crc_basic::AUTO));
				// width=32 poly=0x000000af init=0x00000000 refin=false refout=false xorout=0x00000000 check=0xbd0be338 name="XFER"
				crc_32.push_back(crc_model_t(0x000000af, 0x00000000, 0x00000000, false, false, my_crc_basic::AUTO));
			}
			known_models.push_back(crc_32);

		}

		void print_settings(void);

	private: 
		uint16_t crc_width_; 
		uint32_t polynomial_;
		bool polynomial_range_;
		uint32_t polynomial_start_;
		uint32_t polynomial_end_;
		bool probe_final_xor_;
		uint32_t final_xor_;
		bool probe_initial_;
		uint32_t initial_;
		bool probe_reflected_input_;
		bool reflected_input_;
		bool probe_reflected_output_;
		bool reflected_output_;
  my_crc_basic::FEED_TYPE feed_type_;
  

		uint64_t test_vector_count_;
		bool verbose_;
		bool quiet_;

		std::vector<crc_model_t> crc_model_match_;

	public: 
		void set_crc_width(uint16_t var) { 
			crc_width_ = var; 
			update_test_vector_count(); 
			polynomial_range_ = false;
			polynomial_start_ = 0;
			polynomial_end_ = max_value(crc_width_);
			update_test_vector_count();
		}
		uint16_t crc_width() const { return crc_width_; }
		void set_polynomial(uint32_t var) { polynomial_ = var; update_test_vector_count(); }
		uint32_t polynomial() const { return polynomial_; }
		void set_polynomial_range(bool var) { polynomial_range_ = var; set_crc_width(crc_width_); }
		bool polynomial_range() const { return polynomial_range_; }
		void set_polynomial_start(uint32_t var) { 
			polynomial_start_ = var; 
			polynomial_range_ = true; 
			update_test_vector_count(); 
		}
		uint32_t polynomial_start() const { return polynomial_start_; }
		void set_polynomial_end(uint32_t var) { 
			polynomial_end_ = var; 
			polynomial_range_ = true;
			update_test_vector_count(); 
		}
		uint32_t polynomial_end() const { return polynomial_end_; }
		void set_probe_final_xor(bool var) { probe_final_xor_ = var; update_test_vector_count(); }
		bool probe_final_xor() const { return probe_final_xor_; }
		void set_final_xor(uint32_t var) { final_xor_ = var; }
		uint32_t final_xor() const { return final_xor_; }
		void set_probe_initial(bool var) { probe_initial_ = var; update_test_vector_count(); }
		bool probe_initial() const { return probe_initial_; }
		void set_initial(uint32_t var) { initial_ = var; }
		uint32_t initial() const { return initial_; }
		void set_probe_reflected_input(bool var) { probe_reflected_input_ = var; update_test_vector_count(); }
		bool probe_reflected_input() const { return probe_reflected_input_; }
		void set_reflected_input(bool var) { reflected_input_ = var; }
		bool relfected_input() const { return reflected_input_; }
		void set_probe_reflected_output(bool var) { probe_reflected_output_ = var; update_test_vector_count(); }
		bool probe_reflected_output() const { return probe_reflected_output_; }
		void set_reflected_output(bool var) { reflected_output_ = var; }
		bool reflected_output() const { return reflected_output_; }

  my_crc_basic::FEED_TYPE feed_type() const { return feed_type_; }
  void set_feed_type(my_crc_basic::FEED_TYPE var) { feed_type_ = var; } 

		uint64_t test_vector_count() const { return test_vector_count_; }
		void set_verbose(bool var) { verbose_ = var; }
		bool verbose() const { return verbose_; }
		void set_quiet(bool var) { quiet_ = var; }
		bool quiet() const { return quiet_; }

		std::vector<crc_model_t> crc_model_match() const { return crc_model_match_; }

	private:

		struct timeval start_time;
		struct timeval current_time;

		boost::mutex mymutex;

		uint64_t get_delta_time_in_ms(struct timeval const& start);
  void show_hit(crc_model_t model, std::vector<test_vector_t> test_vectors);
		void print_stats(void);
  std::string feed_type_to_str(my_crc_basic::FEED_TYPE feed_type);

		void update_test_vector_count()
		{
			test_vector_count_ = 0;

			// TODO: Check polynomial range and throw exception if too large
			if (polynomial_ > 0) {
				test_vector_count_ = 1;
			} else if (polynomial_range_) {
				test_vector_count_ = (uint64_t)polynomial_end_ - (uint64_t)polynomial_start_;
			} else {
				test_vector_count_ = (uint64_t)max_value(crc_width_);
			}

			if (probe_final_xor_)
				test_vector_count_ *= (uint64_t)max_value(crc_width_);

			if (probe_initial_)
				test_vector_count_ *= (uint64_t)max_value(crc_width_);

			if (probe_reflected_input_)
				test_vector_count_ *= 2;

			if (probe_reflected_output_)
				test_vector_count_ *= 2;

		}

	public: 

		uint64_t crc_steps;
		static int bool_to_int(bool v);
		static bool int_to_bool(int v);
		static std::string bool_to_str(bool v);
		static std::string number_to_str(uint64_t v);

		static boost::dynamic_bitset<> convert_uint8_to_bitset(const uint8_t array[], size_t size);
		static boost::dynamic_bitset<> convert_string_to_bitset(std::string str);

		static uint32_t max_value(uint8_t width) { return (uint32_t)(((uint64_t)1 << width) - 1); }
	
		void set_parameters(	uint16_t crc_width, 
								uint32_t polynomial, 
								bool probe_final_xor, 
								uint32_t final_xor, 
								bool probe_initial, 
								uint32_t initial, 
								bool probe_reflected_input, 
					bool probe_reflected_output,
					my_crc_basic::FEED_TYPE feed_type)
		{
			set_crc_width(crc_width);
			set_polynomial(polynomial);
			set_probe_final_xor(probe_final_xor);
			set_final_xor(final_xor);
			set_probe_initial(probe_initial);
			set_initial(initial);
			set_probe_reflected_input(probe_reflected_input);
			set_probe_reflected_output(probe_reflected_output);
			set_feed_type(feed_type);
		}

		// TODO: This does not need to return anything
		bool brute_force(	uint32_t search_poly_start, 
							uint32_t search_poly_end, 
							std::vector<test_vector_t> test_vectors);
		int do_brute_force(int num_threads, std::vector<test_vector_t> test_vectors);

	private:

		std::vector< std::vector<crc_model_t> > known_models;

};

#endif
