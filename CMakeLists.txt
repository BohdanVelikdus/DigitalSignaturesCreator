cmake_minimum_required(VERSION 3.28)

set(majorVersion 1)
set(minorVersion 0)
set(minorVersionStr "${minorVersion}")
set(projectVersion "${majorVersion}.${minorVersionStr}")

project(DigitalSignaturesCreator VERSION ${projectVersion} LANGUAGES CXX)

set(OSBitness 32)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(OSBitness 64)
endif()

set(FullDirectory ${CMAKE_SOURCE_DIR}/bin/${CMAKE_SYSTEM_NAME}${OSBitness}/${CMAKE_BUILD_TYPE})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${FullDirectory})

include(CTest)
add_subdirectory(./external)
add_subdirectory(./DigitalSignaturesCreator)