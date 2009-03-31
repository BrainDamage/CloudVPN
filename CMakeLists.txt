
cmake_minimum_required(VERSION 2.6)

project(CLOUDVPN)

set(CMAKE_C_FLAGS $ENV{CFLAGS})
include_directories(include/)

file(GLOB sources src/*.cpp)
add_executable(cloudvpn ${sources})
target_link_libraries(cloudvpn ssl crypt)

install(TARGETS cloudvpn DESTINATION bin)

