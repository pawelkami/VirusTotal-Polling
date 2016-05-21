cmake_minimum_required(VERSION 2.8)
project(VirusTotal_Polling)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external_libraries/TKOM)

include_directories(
                    .
                    ./external_libraries
                    ./external_libraries/TKOM/src)



set(SOURCE_FILES
        src/Configuration.cpp
        src/Configuration.h
        src/main.cpp src/Logger.cpp src/Logger.h src/HttpClient.cpp src/HttpClient.h src/HttpRequest.cpp src/HttpRequest.h src/JsonObject.cpp src/JsonObject.h src/VirusTotalLogic.cpp src/VirusTotalLogic.h src/Utils.h src/Utils.cpp)

set(PROJECT_LINK_LIBS
        ${CMAKE_CURRENT_SOURCE_DIR}/external_libraries/TKOM)


add_executable(VirusTotal_Polling ${SOURCE_FILES})

target_link_libraries(VirusTotal_Polling htmlparser)