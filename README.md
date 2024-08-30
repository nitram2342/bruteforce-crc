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


Install
-------

in general, you may use the bruteforcer from the directory where you compiled the code. If you like to install the bruteforcer into your system, you may run the 'install' target:

\> sudo make install


Run
----

Minimum input:

<pre>
./bruteforce-crc --file [filename] --width [crc-width] --offs-crc [offset to start of crc] --start [start of data] --end [end of data]
</pre>

Input file is an ASCII representation of a binary string, for example:

<pre>
01101100100000111010000110001101011110000000001001111111010
00010000000011001011001001100110111111000001101000101000101
11010111001110001101101100101110111101101010010010011100111
</pre>

If your input is hex-bytes, just use the Perl script "rewrite-as.pl" to convert your input into a format the bruteforcer expects, for example:

<pre>
perl rewrite-as.pl bits test_hexbytes.txt > test_bitmsg.txt
</pre>

The brute-forcer expects simple newlines as line endings. If you have Windows text files ending in \r\n, you need to convert them.

Back to the example, in this example the CRC is 10 bits long and starts at bit 49:

<pre>
[--------------------data-----------------------][---CRC--]
01101100100000111010000110001101011110000000001001111111010
</pre>

The command line for this example would be:

<pre>
./bruteforce-crc --verbose 1 --file data.txt --start 0 --end 49 --width 10 --offs-crc 49 --probe-initial true

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


Credits
--------

* Martyn Pittuck (https://github.com/martynp) made a major rework of the code base and contributed a lot of code
* Solomon Tan (https://github.com/solomonbstoner) fixed issues with reflection and improved example code generation