
cmake_minimum_required(VERSION 2.6)

project(CLOUDVPN)

set(CMAKE_C_FLAGS $ENV{CFLAGS})
set(CMAKE_CXX_FLAGS $ENV{CXXFLAGS})
include_directories(include/)

#main binary
file(GLOB sources src/*.cpp)
add_executable(cloudvpn ${sources})
add_dependencies(cloudvpn common)
target_link_libraries(cloudvpn ssl crypt)

