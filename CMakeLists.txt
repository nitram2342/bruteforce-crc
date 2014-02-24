PROJECT(BRUTEFORCE_CRC)
cmake_minimum_required(VERSION 2.6)

add_definitions(-Wall -O3 -ggdb)

# enable compiler output:
set(CMAKE_VERBOSE_MAKEFILE true)

# Boost
find_package(PkgConfig)
#set(Boost_USE_STATIC_LIBS   ON)
set(Boost_USE_MULTITHREADED ON)

find_package(Boost REQUIRED COMPONENTS program_options system regex thread)
if(Boost_FOUND)
        include_directories(${Boost_INCLUDE_DIRS})
        set(LIBS ${LIBS} ${Boost_LIBRARIES}) 	
endif()

include_directories(.)

set(BRUTEFORCE_CRC_CMD bruteforce-crc.cc)
add_executable(bruteforce-crc ${BRUTEFORCE_CRC_CMD})
target_link_libraries(bruteforce-crc ${LIBS})

set(GENERATE_TEST_DATA_CMD generate-test-data.cc)
add_executable(generate-test-data ${GENERATE_TEST_DATA_CMD})
target_link_libraries(generate-test-data ${LIBS})
