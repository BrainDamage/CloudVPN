
cmake_minimum_required(VERSION 2.6)

project(CLOUDVPN)

set(CMAKE_C_FLAGS $ENV{CFLAGS})
include_directories(include/)

#main binary
file(GLOB sources src/*.cpp)
add_executable(cloudvpn ${sources})
target_link_libraries(cloudvpn ssl crypt)

#auths and gates
file(GLOB clients clients/*)
foreach(i ${clients})
	get_filename_component(fn ${i} NAME)

	message("Found client: " ${fn})

	#try to build all sources, possibly include local cmake list.
	#If there are no sources, build depends solely on the list.
	
	file(GLOB s ${i}/*.c ${i}/*.cpp)
	
	if(s)
		add_executable(${fn} ${s})
	endif(s)

	include(${i}/CMakeLists.txt OPTIONAL)
endforeach(i)


