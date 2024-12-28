cmake_minimum_required(VERSION 3.16)
project(shepherd VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(YAML-CPP REQUIRED yaml-cpp)

add_custom_target(bpf_programs ALL
    COMMAND make -C ${CMAKE_SOURCE_DIR} bpf
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Compiling BPF programs"
)

add_executable(shepherd
    src/main.cpp
    src/shepherd.cpp
)

target_include_directories(shepherd PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${LIBBPF_INCLUDE_DIRS}
    ${YAML-CPP_INCLUDE_DIRS}
)

target_link_libraries(shepherd PRIVATE
    ${LIBBPF_LIBRARIES}
    ${YAML-CPP_LIBRARIES}
    elf # Required by libbpf
    z   # Required by libbpf
)

install(TARGETS shepherd RUNTIME DESTINATION bin)

add_custom_command(TARGET shepherd POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/.output
    ${CMAKE_BINARY_DIR}/bpf
)