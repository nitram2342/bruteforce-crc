These files are part of a CRC parameter brute-forcing tool. Please have a look at
http://sitsec.net/blog/2012/02/10/brute-forcing-crc-parameters/

Author: Martin Schobert <schobert@sitsec.net>

Licence
--------

This code is published under the Boost Software Licence.
http://www.boost.org/users/license.html

Dependencies
-------------

- Cmake
- Boost
  - boost_program_options
  - boost_system
  - boost_regex
  - boost_thread
  - boost_test
  - boost_filesystem

To install these on a Linux, you may run:

$ sudo apt-get install cmake libboost-program-options-dev libboost-system-dev libboost-regex-dev \
  libboost-thread-dev libboost-test-dev libboost-filesystem-dev


Compile
--------

> cmake .

Check for errors and install missing dependencies.

> make

