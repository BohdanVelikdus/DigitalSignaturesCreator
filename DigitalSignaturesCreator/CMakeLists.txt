
set(TEST_PATH "${CMAKE_CURRENT_SOURCE_DIR}/certificates_test")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/DigitalSignaturesCreator.h.in ${CMAKE_BINARY_DIR}/DigitalSignaturesCreator.h)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(OPENSSL_USE_STATIC_LIBS TRUE)

find_package(OpenSSL QUIET)

if(OpenSSL_FOUND)
    message(STATUS "OpenSSL found!")
else()
    message(STATUS "OpenSSL not found, try using a conan!")
    find_package(OpenSSL REQUIRED CONFIG)
endif()

# Creating the CertificateManager static library
add_library(CertificateManager STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/CertificateManager.cpp)
target_include_directories(CertificateManager PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIRS}
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

# Enable Testing
if(BUILD_TESTING)
    add_executable(testing 
        ${CMAKE_CURRENT_SOURCE_DIR}/certificates_test/tests.cpp
        ${Program_SRC_FILES}
    )
    
    target_include_directories(testing PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
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
