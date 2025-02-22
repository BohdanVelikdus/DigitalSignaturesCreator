cmake_minimum_required(VERSION 3.28)

set(majorVersion 1)
set(minorVersion 0)
set(minorVersionStr "${minorVersion}")
set(projectVersion "${majorVersion}.${minorVersionStr}")

project(DigitalSignaturesCreator VERSION ${projectVersion} LANGUAGES CXX)

include(CTest)
add_subdirectory(./external)
add_subdirectory(./DigitalSignaturesCreator)