
cmake_minimum_required(VERSION 2.6)

project(CLOUDVPN)

set(CMAKE_C_FLAGS $ENV{CFLAGS})
include_directories(include/)

#first, make common sources

file(GLOB commonsources common/*.cpp)
add_library(common STATIC ${commonsources})
get_target_property(common common LOCATION)

#main binary
file(GLOB sources src/*.cpp)
add_executable(cloudvpn ${sources})
add_dependencies(cloudvpn common)
target_link_libraries(cloudvpn ssl crypt ${common})

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
		add_dependencies(${fn} common)
		target_link_libraries(${fn} ${common})
	endif(s)

	include(${i}/CMakeLists.txt OPTIONAL)
endforeach(i)


