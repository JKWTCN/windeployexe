cmake_minimum_required(VERSION 3.10)

# Get current year for copyright
string(TIMESTAMP PROJECT_YEAR "%Y")

project(win_deploy
    VERSION 1.1.1.0
    DESCRIPTION "Windows DLL dependency analyzer and deployment tool"
    LANGUAGES CXX
)

# Project version configuration (explicit for flexibility)
set(PROJECT_VERSION_MAJOR 1)
set(PROJECT_VERSION_MINOR 1)
set(PROJECT_VERSION_PATCH 1)
set(PROJECT_VERSION_TWEAK 0)
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}.${PROJECT_VERSION_TWEAK}")
set(PROJECT_NAME "win_deploy")

# Set the C++ standard to C++ 17
set(CMAKE_CXX_STANDARD 17)
set(CXX_STANDARD_REQUIRED true)
if(MSVC)
    add_definitions("/Zc:__cplusplus" -DUNICODE=1)
endif()
include_directories("${CMAKE_SOURCE_DIR}")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(
    SOURCES
    main.cc
)
add_executable(
    win_deploy
    ${SOURCES}
    ${CMAKE_BINARY_DIR}/version.rc
)

# Set version properties for the executable
set_target_properties(win_deploy PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME "win_deploy"
)

# Configure version header file (optional)
configure_file(
    ${CMAKE_SOURCE_DIR}/version.h.in
    ${CMAKE_BINARY_DIR}/version.h
    @ONLY
)

# Configure Windows version resource
configure_file(
    ${CMAKE_SOURCE_DIR}/version.rc.in
    ${CMAKE_BINARY_DIR}/version.rc
    @ONLY
)

# Add version information to the source files
target_compile_definitions(win_deploy PRIVATE
    PROJECT_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    PROJECT_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    PROJECT_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    PROJECT_VERSION_TWEAK=${PROJECT_VERSION_TWEAK}
    PROJECT_VERSION="${PROJECT_VERSION}"
)

# Display build information
message(STATUS "Project: ${PROJECT_NAME}")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Description: ${PROJECT_DESCRIPTION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
