cmake_minimum_required(VERSION 3.5)
project(updater)

find_package(PkgConfig REQUIRED)
find_package(CURL REQUIRED)

pkg_check_modules(MINIZIP REQUIRED minizip)


# Inclusion des répertoires d'en-têtes
include_directories(${CURL_INCLUDE_DIRS} ${MINIZIP_INCLUDE_DIRS})


# Ajout des sources de l'exécutable
add_executable(updater main.c)

# Liaison avec les bibliothèques
target_link_libraries(updater PRIVATE ${CURL_LIBRARIES} ${MINIZIP_LIBRARIES})

# Si vous êtes sur un système UNIX, ajoutez cette option
if (UNIX)
    set(CMAKE_EXE_LINKER_FLAGS "-Wl,-export-dynamic")
endif (UNIX)

# Spécifie le répertoire de sortie de l'exécutable
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR})
