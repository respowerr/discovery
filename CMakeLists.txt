cmake_minimum_required(VERSION 3.5)
project(test_comp)

find_package(PkgConfig REQUIRED)

pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
pkg_check_modules(GDK_PIXBUF REQUIRED gdk-pixbuf-2.0)

include_directories(${GTK3_INCLUDE_DIRS} ${GDK_PIXBUF_INCLUDE_DIRS})
link_directories(${GTK3_LIBRARY_DIRS} ${GDK_PIXBUF_LIBRARY_DIRS})
add_definitions(${GTK3_CFLAGS_OTHER})

add_executable(test_comp WIN32 main.c)
target_link_libraries(test_comp ${GTK3_LIBRARIES} ${GDK_PIXBUF_LIBRARIES})

INCLUDE_DIRECTORIES(${GTK3_INCLUDE_DIRS})
LINK_DIRECTORIES(${GTK3_LIBRARY_DIRS})

ADD_DEFINITIONS(${GTK3_CFLAGS_OTHER})

if (UNIX)
    set(CMAKE_EXE_LINKER_FLAGS "-Wl,-export-dynamic")
endif (UNIX)

# Lie à l'éxecutable la librairie GTK+
TARGET_LINK_LIBRARIES(test_comp ${GTK3_LIBRARIES})