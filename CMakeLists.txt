cmake_minimum_required(VERSION 3.5)
project(discovery)

# Recherche des paquets requis avec PkgConfig
find_package(PkgConfig REQUIRED)
find_package(CURL REQUIRED)

pkg_check_modules(GTK3 REQUIRED gtk+-3.0)
pkg_check_modules(GDK_PIXBUF REQUIRED gdk-pixbuf-2.0)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

include_directories(${GTK3_INCLUDE_DIRS} ${GDK_PIXBUF_INCLUDE_DIRS} ${SQLITE3_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS})

add_definitions(${GTK3_CFLAGS_OTHER})

add_executable(discovery WIN32 main.c panel.c verif_whois.c verif_robot.c verif_html.c verif_cookie.c src/style.css)

target_link_libraries(discovery ${GTK3_LIBRARIES} ${GDK_PIXBUF_LIBRARIES} ${CURL_LIBRARIES} ${SQLITE3_LIBRARIES})

if (UNIX)
    set(CMAKE_EXE_LINKER_FLAGS "-Wl,-export-dynamic")
endif (UNIX)

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR})
