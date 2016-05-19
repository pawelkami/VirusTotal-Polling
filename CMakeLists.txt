cmake_minimum_required(VERSION 2.8)
project(VirusTotal_Polling)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external_libraries/TKOM)

include_directories(
                    .
                    ./external_libraries)

set(SOURCE_FILES
        src/Configuration.cpp
        src/Configuration.h
        src/main.cpp)

set(PROJECT_LINK_LIBS
        ${CMAKE_CURRENT_SOURCE_DIR}/external_libraries/TKOM)


add_executable(VirusTotal_Polling ${SOURCE_FILES})

target_link_libraries(VirusTotal_Polling ${PROJECT_LINK_LIBS})