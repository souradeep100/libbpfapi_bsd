# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/edguer/Projects/libbpfapi_bsd

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/edguer/Projects/libbpfapi_bsd

# Include any dependencies generated for this target.
include CMakeFiles/bpf_svc.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/bpf_svc.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/bpf_svc.dir/flags.make

CMakeFiles/bpf_svc.dir/src/service/common.cpp.o: CMakeFiles/bpf_svc.dir/flags.make
CMakeFiles/bpf_svc.dir/src/service/common.cpp.o: src/service/common.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/edguer/Projects/libbpfapi_bsd/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/bpf_svc.dir/src/service/common.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/bpf_svc.dir/src/service/common.cpp.o -c /home/edguer/Projects/libbpfapi_bsd/src/service/common.cpp

CMakeFiles/bpf_svc.dir/src/service/common.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/bpf_svc.dir/src/service/common.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/edguer/Projects/libbpfapi_bsd/src/service/common.cpp > CMakeFiles/bpf_svc.dir/src/service/common.cpp.i

CMakeFiles/bpf_svc.dir/src/service/common.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/bpf_svc.dir/src/service/common.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/edguer/Projects/libbpfapi_bsd/src/service/common.cpp -o CMakeFiles/bpf_svc.dir/src/service/common.cpp.s

CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.o: CMakeFiles/bpf_svc.dir/flags.make
CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.o: src/service/ebpf_verify_and_load_program.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/edguer/Projects/libbpfapi_bsd/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.o -c /home/edguer/Projects/libbpfapi_bsd/src/service/ebpf_verify_and_load_program.cpp

CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/edguer/Projects/libbpfapi_bsd/src/service/ebpf_verify_and_load_program.cpp > CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.i

CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/edguer/Projects/libbpfapi_bsd/src/service/ebpf_verify_and_load_program.cpp -o CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.s

CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.o: CMakeFiles/bpf_svc.dir/flags.make
CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.o: src/service/ebpf_verify_program.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/edguer/Projects/libbpfapi_bsd/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.o -c /home/edguer/Projects/libbpfapi_bsd/src/service/ebpf_verify_program.cpp

CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/edguer/Projects/libbpfapi_bsd/src/service/ebpf_verify_program.cpp > CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.i

CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/edguer/Projects/libbpfapi_bsd/src/service/ebpf_verify_program.cpp -o CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.s

CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.o: CMakeFiles/bpf_svc.dir/flags.make
CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.o: src/prototypes/bpf_svc_svc.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/edguer/Projects/libbpfapi_bsd/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.o   -c /home/edguer/Projects/libbpfapi_bsd/src/prototypes/bpf_svc_svc.c

CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/edguer/Projects/libbpfapi_bsd/src/prototypes/bpf_svc_svc.c > CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.i

CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/edguer/Projects/libbpfapi_bsd/src/prototypes/bpf_svc_svc.c -o CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.s

CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.o: CMakeFiles/bpf_svc.dir/flags.make
CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.o: src/prototypes/bpf_svc_xdr.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/edguer/Projects/libbpfapi_bsd/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.o   -c /home/edguer/Projects/libbpfapi_bsd/src/prototypes/bpf_svc_xdr.c

CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/edguer/Projects/libbpfapi_bsd/src/prototypes/bpf_svc_xdr.c > CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.i

CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/edguer/Projects/libbpfapi_bsd/src/prototypes/bpf_svc_xdr.c -o CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.s

# Object files for target bpf_svc
bpf_svc_OBJECTS = \
"CMakeFiles/bpf_svc.dir/src/service/common.cpp.o" \
"CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.o" \
"CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.o" \
"CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.o" \
"CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.o"

# External object files for target bpf_svc
bpf_svc_EXTERNAL_OBJECTS =

bpf_svc: CMakeFiles/bpf_svc.dir/src/service/common.cpp.o
bpf_svc: CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_and_load_program.cpp.o
bpf_svc: CMakeFiles/bpf_svc.dir/src/service/ebpf_verify_program.cpp.o
bpf_svc: CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_svc.c.o
bpf_svc: CMakeFiles/bpf_svc.dir/src/prototypes/bpf_svc_xdr.c.o
bpf_svc: CMakeFiles/bpf_svc.dir/build.make
bpf_svc: external/ebpf-verifier/libebpfverifier.a
bpf_svc: /usr/lib/x86_64-linux-gnu/libyaml-cpp.so.0.6.2
bpf_svc: CMakeFiles/bpf_svc.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/edguer/Projects/libbpfapi_bsd/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking CXX executable bpf_svc"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/bpf_svc.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/bpf_svc.dir/build: bpf_svc

.PHONY : CMakeFiles/bpf_svc.dir/build

CMakeFiles/bpf_svc.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/bpf_svc.dir/cmake_clean.cmake
.PHONY : CMakeFiles/bpf_svc.dir/clean

CMakeFiles/bpf_svc.dir/depend:
	cd /home/edguer/Projects/libbpfapi_bsd && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/edguer/Projects/libbpfapi_bsd /home/edguer/Projects/libbpfapi_bsd /home/edguer/Projects/libbpfapi_bsd /home/edguer/Projects/libbpfapi_bsd /home/edguer/Projects/libbpfapi_bsd/CMakeFiles/bpf_svc.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/bpf_svc.dir/depend

