cmake_minimum_required(VERSION 3.28)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# for output directory
set(OSBitness 32)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(OSBitness 64)
endif()
#directory output 
set(FullDirectory ${CMAKE_CURRENT_SOURCE_DIR}/bin/${CMAKE_SYSTEM_NAME}${OSBitness}/${CMAKE_BUILD_TYPE})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${FullDirectory})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${FullDirectory}/lib")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${FullDirectory}/lib")

if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/dependencies/conan_toolchain.cmake")
    include("${CMAKE_CURRENT_BINARY_DIR}/conan_toolchain.cmake")
    message(STATUS "Use toolchain file")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Building in Debug mode")
    add_compile_definitions(DEBUG)
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
# for dependencies

# Use Conan toolchain if available
set(CMAKE_EXPORT_COMPILE_COMMANDS YES)
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/dependencies)

# enabling Testing routines 
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/external)
set(TEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/certificates_test")

project(DigitalSignaturesCreator VERSION ${projectVersion} LANGUAGES CXX)

#configuration file for versioning purpose
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/DigitalSignaturesCreator.h.in ${CMAKE_BINARY_DIR}/DigitalSignaturesCreator.h)

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL QUIET)

if(OpenSSL_FOUND)
    message(STATUS "OpenSSL found!")
else()
    message(STATUS "OpenSSL not found, try using a conan!")
    find_package(OpenSSL REQUIRED CONFIG)
endif()

message(STATUS "Headers ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Libs ${OPENSSL_LIBRARIES}")

# Creating the CertificateManager static library
add_library(CertificateManager STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/CertificateManager.cpp)
target_include_directories(CertificateManager PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(CertificateManager PUBLIC 
    ${OPENSSL_LIBRARIES}
)

# Creating the HashManager static library
add_library(HashManager STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/HashManager.cpp)
target_include_directories(HashManager PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
)
target_link_libraries(HashManager PUBLIC 
    ${OPENSSL_LIBRARIES}
)

# Add the code for the program functionality
set(Program_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(Program_SRC_FILES ${CMAKE_CURRENT_SOURCE_DIR}/src/Program.cpp)

add_executable(${PROJECT_NAME} 
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
    ${Program_SRC_FILES}
)

target_include_directories(${PROJECT_NAME} PUBLIC 
    ${OPENSSL_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PUBLIC
    ${OPENSSL_LIBRARIES}
    CertificateManager
    HashManager
)

include(CTest)
# Enable Testing
if(BUILD_TESTING)
    add_executable(testing 
        ${CMAKE_CURRENT_SOURCE_DIR}/certificates_test/tests.cpp
        ${Program_SRC_FILES}
    )
    
    target_include_directories(testing PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_BINARY_DIR}
    )
    target_link_libraries(testing PRIVATE 
        GTest::gtest_main
        CertificateManager
        HashManager
    )    
    
    set_target_properties(testing PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${FullDirectory}/tests"
    )

    include(GoogleTest)
    gtest_discover_tests(testing)
endif()
