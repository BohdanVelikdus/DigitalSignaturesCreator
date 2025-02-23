
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/DigitalSignaturesCreator.h.in ${CMAKE_BINARY_DIR}/DigitalSignaturesCreator.h)

set(OPENSSL_USE_STATIC_LIBS TRUE)
#find_package(OpenSSL REQUIRED)

if(OpenSSL_FOUND)
    message(STATUS "OpenSSL found!")
else()
    message(STATUS "OpenSSL not found, even submodule does not work!")
endif()

file(GLOB SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PUBLIC 
    ${OPENSSL_INCLUDE_DIRS}
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} PUBLIC
    ${OPENSSL_LIBRARIES}
)

if(BUILD_TESTING)

endif()