cmake_minimum_required(VERSION 3.5)
project(discovery)

find_package(PkgConfig REQUIRED)

pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
pkg_check_modules(GDK_PIXBUF REQUIRED gdk-pixbuf-2.0)

include_directories(${GTK3_INCLUDE_DIRS} ${GDK_PIXBUF_INCLUDE_DIRS})
link_directories(${GTK3_LIBRARY_DIRS} ${GDK_PIXBUF_LIBRARY_DIRS})
add_definitions(${GTK3_CFLAGS_OTHER})

add_executable(discovery WIN32 main.c)
target_link_libraries(discovery ${GTK3_LIBRARIES} ${GDK_PIXBUF_LIBRARIES})

include_directories(${GTK3_INCLUDE_DIRS})
link_directories(${GTK3_LIBRARY_DIRS})
add_definitions(${GTK3_CFLAGS_OTHER})

if (UNIX)
    set(CMAKE_EXE_LINKER_FLAGS "-Wl,-export-dynamic")
endif (UNIX)

target_link_libraries(discovery ${GTK3_LIBRARIES})

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR})
