
cmake_minimum_required(VERSION 2.6)

project(CLOUDVPN)

include_directories(include/)
file(GLOB sources src/*.cpp)
add_executable(cloudvpn ${sources})
target_link_libraries(cloudvpn ssl crypt)

