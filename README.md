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
  - boost\_program\_options
  - boost\_system
  - boost\_regex
  - boost\_thread

$ sudo apt-get install cmake libboost-program-options-dev libboost-system-dev libboost-regex-dev \
  libboost-thread-dev libboost-test-dev libboost-filesystem-dev

Compile
--------

\> cmake .

Check for errors and install missing dependencies.

\> make

Build bruteforce-crc and ./bin/test*

\> make test

Run tests (can take a long time) 

Run
----

Minimum input:

./bruteforce-crc --file [filename] --width [crc-width] --offs-crc [offset to start of crc] --start [start of data] --end [end of data]

Input file is an ascii representation of a binary string, for example:

<pre>
01101100100000111010000110001101011110000000001001111111010
00010000000011001011001001100110111111000001101000101000101
11010111001110001101101100101110111101101010010010011100111
</pre>

In this example the CRC is 10 bits long and starts at bit 49:

<pre>
[--------------------data-----------------------][---CRC--]
01101100100000111010000110001101011110000000001001111111010
</pre>

The command line for this example would be:

<pre>
./buteforce-crc --file data.txt --width=10 --offs-crc 49 --start 0 --end 49

Options List [* Required]:

  --file arg                   * File containing messages
  --width arg                  * CRC width
  --offs-crc arg               * CRC's offset
  --start arg                  * Calculate CRC from this offset
  --end arg                    * Calculate CRC up to this offset (not included)
  --output arg                 Output file for matched crc settings
  --verbose arg                Enable verbose output
  --poly arg                   Truncated polynomial (default: bruteforced)
  --poly-start arg             Start of polynomial search space (default: 0)
  --poly-end arg               End of polynomial search space (default (2^width - 1))
  --threads arg                Number of threads (default: 4)
  --initial arg                Set intial value (default: 0)
  --probe-initial arg          Bruteforce the intial, overrides initial (default: true)
  --final-xor arg              Final xor (default: 0)
  --probe-final-xor arg        Bruteforce the final-xor, overrides final-xor (default: false)
  --probe-reflected-input arg  Probe for reflect input (default: false)
  --probe-reflected-output arg Probe for reflect remainder output (default: false)
</pre>


