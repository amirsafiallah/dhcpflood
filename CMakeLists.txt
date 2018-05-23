cmake_minimum_required(VERSION 3.10)
project(dhcpflood)

set(CMAKE_CXX_STANDARD 17)

find_package(Threads REQUIRED)

add_executable(dhcpflood main.cpp DHCPFlood.cpp DHCPFlood.h)
target_link_libraries(dhcpflood tins ${CMAKE_THREAD_LIBS_INIT})
