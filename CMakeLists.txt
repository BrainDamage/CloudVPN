
cmake_minimum_required(VERSION 2.6)

project(CLOUDVPN)

set(target $ENV{TARGET}) #crosscompiling
if(target)
	set(CMAKE_C_COMPILER "${target}-gcc")
	set(CMAKE_CXX_COMPILER "${target}-g++")
	message("Target platform: " ${target})
endif(target)

set(extra-libs $ENV{EXTRA_LIBS}) #for winsock2 and similar
if(extra-libs)
	message("Extra libraries added: " ${extra-libs})
endif(extra-libs)

set(bin-extension $ENV{BIN_EXTENSION}) #for windows crosscompile
if(bin-extension)
	message("Executables will be *." ${bin-extension})
	set(bin-extension ".${bin-extension}")
endif(bin-extension)

set(CMAKE_C_FLAGS $ENV{CFLAGS})
set(CMAKE_CXX_FLAGS $ENV{CXXFLAGS})
set(CMAKE_LINK_FLAGS $ENV{LDFLAGS})
include_directories(include/)
message("CFLAGS are set to '" ${CMAKE_C_FLAGS} "'")
message("CXXFLAGS are set to '" ${CMAKE_CXX_FLAGS} "'")
message("LDFLAGS are set to '" ${CMAKE_LINK_FLAGS} "'")

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
	set(tname ${fn}${bin-extension})
	
	if(s)
		add_executable(${tname} ${s})
		add_dependencies(${tname} common)
	 	target_link_libraries(${tname} ${common} ${extra-libs})
		install (TARGETS ${tname} DESTINATION "bin/")
	endif(s)

	include(${i}/CMakeLists.txt OPTIONAL)
endforeach(i)

