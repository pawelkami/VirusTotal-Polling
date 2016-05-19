cmake_minimum_required(VERSION 2.8)
project(VirusTotal_Polling)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

include_directories(
                    .
                    ./external_libraries)

set(SOURCE_FILES
        src/Configuration.cpp
        src/Configuration.h
        src/main.cpp)

add_executable(VirusTotal_Polling ${SOURCE_FILES})