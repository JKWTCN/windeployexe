cmake_minimum_required(VERSION 3.10)

project(win_deploy VERSION 1.0)
# set the C++ standard to C++ 17
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
)
