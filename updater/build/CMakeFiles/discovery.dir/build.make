# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = "C:\Program Files\CMake\bin\cmake.exe"

# The command to remove a file.
RM = "C:\Program Files\CMake\bin\cmake.exe" -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = C:\Users\jules\Documents\discovery

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = C:\Users\jules\Documents\discovery\build

# Include any dependencies generated for this target.
include CMakeFiles/discovery.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/discovery.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/discovery.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/discovery.dir/flags.make

CMakeFiles/discovery.dir/main.c.obj: CMakeFiles/discovery.dir/flags.make
CMakeFiles/discovery.dir/main.c.obj: CMakeFiles/discovery.dir/includes_C.rsp
CMakeFiles/discovery.dir/main.c.obj: C:/Users/jules/Documents/discovery/main.c
CMakeFiles/discovery.dir/main.c.obj: CMakeFiles/discovery.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=C:\Users\jules\Documents\discovery\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/discovery.dir/main.c.obj"
	C:\msys64\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/discovery.dir/main.c.obj -MF CMakeFiles\discovery.dir\main.c.obj.d -o CMakeFiles\discovery.dir\main.c.obj -c C:\Users\jules\Documents\discovery\main.c

CMakeFiles/discovery.dir/main.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/discovery.dir/main.c.i"
	C:\msys64\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\jules\Documents\discovery\main.c > CMakeFiles\discovery.dir\main.c.i

CMakeFiles/discovery.dir/main.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/discovery.dir/main.c.s"
	C:\msys64\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\jules\Documents\discovery\main.c -o CMakeFiles\discovery.dir\main.c.s

CMakeFiles/discovery.dir/src/panel.c.obj: CMakeFiles/discovery.dir/flags.make
CMakeFiles/discovery.dir/src/panel.c.obj: CMakeFiles/discovery.dir/includes_C.rsp
CMakeFiles/discovery.dir/src/panel.c.obj: C:/Users/jules/Documents/discovery/src/panel.c
CMakeFiles/discovery.dir/src/panel.c.obj: CMakeFiles/discovery.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=C:\Users\jules\Documents\discovery\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/discovery.dir/src/panel.c.obj"
	C:\msys64\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/discovery.dir/src/panel.c.obj -MF CMakeFiles\discovery.dir\src\panel.c.obj.d -o CMakeFiles\discovery.dir\src\panel.c.obj -c C:\Users\jules\Documents\discovery\src\panel.c

CMakeFiles/discovery.dir/src/panel.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing C source to CMakeFiles/discovery.dir/src/panel.c.i"
	C:\msys64\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\jules\Documents\discovery\src\panel.c > CMakeFiles\discovery.dir\src\panel.c.i

CMakeFiles/discovery.dir/src/panel.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling C source to assembly CMakeFiles/discovery.dir/src/panel.c.s"
	C:\msys64\mingw64\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\jules\Documents\discovery\src\panel.c -o CMakeFiles\discovery.dir\src\panel.c.s

# Object files for target discovery
discovery_OBJECTS = \
"CMakeFiles/discovery.dir/main.c.obj" \
"CMakeFiles/discovery.dir/src/panel.c.obj"

# External object files for target discovery
discovery_EXTERNAL_OBJECTS =

C:/Users/jules/Documents/discovery/discovery.exe: CMakeFiles/discovery.dir/main.c.obj
C:/Users/jules/Documents/discovery/discovery.exe: CMakeFiles/discovery.dir/src/panel.c.obj
C:/Users/jules/Documents/discovery/discovery.exe: CMakeFiles/discovery.dir/build.make
C:/Users/jules/Documents/discovery/discovery.exe: C:/msys64/mingw64/lib/libcurl.dll.a
C:/Users/jules/Documents/discovery/discovery.exe: C:/msys64/mingw64/lib/libcurl.dll.a
C:/Users/jules/Documents/discovery/discovery.exe: CMakeFiles/discovery.dir/linkLibs.rsp
C:/Users/jules/Documents/discovery/discovery.exe: CMakeFiles/discovery.dir/objects1.rsp
C:/Users/jules/Documents/discovery/discovery.exe: CMakeFiles/discovery.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=C:\Users\jules\Documents\discovery\build\CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable C:\Users\jules\Documents\discovery\discovery.exe"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\discovery.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/discovery.dir/build: C:/Users/jules/Documents/discovery/discovery.exe
.PHONY : CMakeFiles/discovery.dir/build

CMakeFiles/discovery.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles\discovery.dir\cmake_clean.cmake
.PHONY : CMakeFiles/discovery.dir/clean

CMakeFiles/discovery.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" C:\Users\jules\Documents\discovery C:\Users\jules\Documents\discovery C:\Users\jules\Documents\discovery\build C:\Users\jules\Documents\discovery\build C:\Users\jules\Documents\discovery\build\CMakeFiles\discovery.dir\DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/discovery.dir/depend

