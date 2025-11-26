cmake_minimum_required(VERSION 3.16)
project(pqc_box C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options for static-ish builds (Linux)
option(STATIC_LINK "Prefer static linking where reasonable" OFF)

# Find OpenSSL
find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# Find liboqs (via pkg-config first, then manual)
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(LIBOQS liboqs)
endif()

if(LIBOQS_FOUND)
  add_library(oqs SHARED IMPORTED)
  set_target_properties(oqs PROPERTIES
    IMPORTED_LOCATION "${LIBOQS_LIBDIR}/liboqs.${CMAKE_SHARED_LIBRARY_SUFFIX}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBOQS_INCLUDEDIR}")
  set(LIBOQS_TARGET oqs)
else()
  # Fallback: try common prefixes
  find_path(LIBOQS_INCLUDE_DIR oqs/oqs.h
    PATHS /usr/local/include /opt/homebrew/include /usr/include)
  find_library(LIBOQS_LIBRARY NAMES oqs
    PATHS /usr/local/lib /opt/homebrew/lib /usr/lib)
  if(NOT LIBOQS_INCLUDE_DIR OR NOT LIBOQS_LIBRARY)
    message(FATAL_ERROR "liboqs not found. Install it and/or set PKG_CONFIG_PATH.")
  endif()
  add_library(oqs UNKNOWN IMPORTED)
  set_target_properties(oqs PROPERTIES
    IMPORTED_LOCATION "${LIBOQS_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${LIBOQS_INCLUDE_DIR}")
  set(LIBOQS_TARGET oqs)
endif()

add_executable(pqc_box pqc_box.c)
target_link_libraries(pqc_box PRIVATE ${LIBOQS_TARGET} OpenSSL::Crypto)

# On macOS, embed rpath so the loader finds Homebrew libs
if(APPLE)
  set_target_properties(pqc_box PROPERTIES
    INSTALL_RPATH "@loader_path/../lib;/opt/homebrew/lib;/usr/local/lib")
endif()

# Prefer static on Linux if requested
if(UNIX AND NOT APPLE AND STATIC_LINK)
  target_link_options(pqc_box PRIVATE -static -Wl,--whole-archive -lpthread -Wl,--no-whole-archive)
endif()
