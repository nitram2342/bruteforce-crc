PROJECT(BRUTEFORCE_CRC)
cmake_minimum_required(VERSION 2.6)

add_definitions(-Wall -O3 -ggdb)

# enable compiler output:
set(CMAKE_VERBOSE_MAKEFILE true)

#Setup CMake to run tests
enable_testing()

# Boost
find_package(PkgConfig)

#set(Boost_USE_STATIC_LIBS   ON)
set(Boost_USE_MULTITHREADED ON)

find_package(Boost REQUIRED COMPONENTS program_options system regex thread unit_test_framework filesystem)
if(Boost_FOUND)
        include_directories(${Boost_INCLUDE_DIRS})
        set(LIBS ${LIBS} ${Boost_LIBRARIES}) 	
endif()

include_directories(.)

add_library(crc STATIC crc.cc)
add_library(bf_crc STATIC bf_crc.cc)
target_link_libraries(bf_crc ${LIBS} crc)
set(LIBS ${LIBS} bf_crc) 

set(BRUTEFORCE_CRC_CMD bruteforce-crc.cc)
add_executable(bruteforce-crc ${BRUTEFORCE_CRC_CMD})
target_link_libraries(bruteforce-crc ${LIBS})

set(GENERATE_TEST_DATA_CMD generate-test-data.cc)
add_executable(generate-test-data ${GENERATE_TEST_DATA_CMD})
target_link_libraries(generate-test-data ${LIBS})

# To process brute forcer stolen from http://neyasystems.com/an-engineers-guide-to-unit-testing-cmake-and-boost-unit-tests/
file(GLOB TEST_SRCS RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} tests/*.cc)

#Run through each source
foreach(testSrc ${TEST_SRCS})

        #Extract the filename without an extension (NAME_WE)
        get_filename_component(testName ${testSrc} NAME_WE)

        #Add compile target
        add_executable(${testName} ${testSrc})

        #link to Boost libraries AND your targets and dependencies
        target_link_libraries(${testName} ${Boost_LIBRARIES} ${LIBS})

        #I like to move testing binaries into a testBin directory
        set_target_properties(${testName} PROPERTIES 
            RUNTIME_OUTPUT_DIRECTORY  ${CMAKE_CURRENT_SOURCE_DIR}/bin)

        #Finally add it to test execution - 
        #Notice the WORKING_DIRECTORY and COMMAND
        add_test(NAME ${testName} 
                 WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin
                 COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/bin/${testName} )

endforeach(testSrc)


INSTALL(FILES bruteforce-crc.1 DESTINATION man/man1)
INSTALL(PROGRAMS bruteforce-crc DESTINATION bin)
INSTALL(PROGRAMS rewrite-as.pl DESTINATION bin)
