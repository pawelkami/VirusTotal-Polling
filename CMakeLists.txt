cmake_minimum_required(VERSION 2.8)
project(VirusTotal_Polling)

find_package (Threads)

find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.54.0 COMPONENTS program_options system filesystem REQUIRED)


if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    # Error; with REQUIRED, pkg_search_module() will throw an error by it's own
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external_libraries/TKOM)

include_directories(
                    .
                    ./external_libraries
                    ./external_libraries/TKOM/src)



set(SOURCE_FILES
        src/Configuration.cpp
        src/Configuration.h
        src/main.cpp src/Logger.cpp src/Logger.h src/HttpClient.cpp src/HttpClient.h src/HttpRequest.cpp src/HttpRequest.h src/JsonObject.cpp src/JsonObject.h src/VirusTotalLogic.cpp src/VirusTotalLogic.h src/Utils.h src/Utils.cpp src/HttpResponse.cpp src/HttpResponse.h src/exception/HttpClientException.h src/exception/RequestException.h src/exception/FileException.h src/HttpServer.cpp src/HttpServer.h)

set(PROJECT_LINK_LIBS
        ${CMAKE_CURRENT_SOURCE_DIR}/external_libraries/TKOM)


add_executable(VirusTotal_Polling ${SOURCE_FILES})

target_link_libraries(VirusTotal_Polling htmlparser ${OPENSSL_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(VirusTotal_Polling ${Boost_LIBRARIES} ${Boost_FILESYSTEM_LIBRARY} ${Boost_SYSTEM_LIBRARY})
endif()