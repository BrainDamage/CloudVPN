
cmake_minimum_required(VERSION 2.6)

project(CLOUDVPN)

set(target $ENV{TARGET})
if(target)
	set(CMAKE_C_COMPILER "${target}-gcc")
	set(CMAKE_CXX_COMPILER "${target}-g++")
	message("Target platform: " ${target})
endif(target)

set(CMAKE_C_FLAGS $ENV{CFLAGS})
set(CMAKE_CXX_FLAGS $ENV{CXXFLAGS})
include_directories(include/)
message("CFLAGS are set to '" ${CMAKE_C_FLAGS} "'")
message("CXXFLAGS are set to '" ${CMAKE_CXX_FLAGS} "'")

#first, make common sources

file(GLOB commonsources common/*.cpp)
add_library(common STATIC ${commonsources})
get_target_property(common common LOCATION)

#binaries
file(GLOB src src/*)
foreach(i ${src})
	get_filename_component(fn ${i} NAME)

	message("Found target: " ${fn})

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

