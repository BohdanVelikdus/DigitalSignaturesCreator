cmake_minimum_required(VERSION 3.28)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Building in Debug mode")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Building in Release mode")
else()
    message(WARNING "No build type set, defaulting to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif()

set(majorVersion 1)
set(minorVersion 0)
set(minorVersionStr "${minorVersion}")
set(projectVersion "${majorVersion}.${minorVersionStr}")
set(CMAKE_EXPORT_COMPILE_COMMANDS YES)

project(DigitalSignaturesCreator VERSION ${projectVersion} LANGUAGES CXX)

set(OSBitness 32)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(OSBitness 64)
endif()

set(FullDirectory ${CMAKE_SOURCE_DIR}/bin/${CMAKE_SYSTEM_NAME}${OSBitness}/${CMAKE_BUILD_TYPE})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${FullDirectory})

list(APPEND CMAKE_PREFIX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/exteral/dependecies)

include(CTest)

find_package(OpenSSL QUIET)

add_subdirectory(./external)
add_subdirectory(./DigitalSignaturesCreator)