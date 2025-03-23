cmake_minimum_required(VERSION 3.18)
include_guard(GLOBAL)

project(extism-cpp VERSION 1.0.0 DESCRIPTION "C++ bindings for libextism")
set(CMAKE_CXX_STANDARD 17)

# === Options ===
option(EXTISM_CPP_BUILD_IN_TREE "Use submodules for dependencies" OFF)
option(EXTISM_CPP_WITH_CMAKE_PACKAGE "Generate and install CMake package files" ON)

# === Sources ===
set(extism_cpp_sources
        src/manifest.cpp
        src/current_plugin.cpp
        src/plugin.cpp
        src/function.cpp
        src/extism.cpp
)

# === Dependencies ===
if (EXTISM_CPP_BUILD_IN_TREE)
    message(STATUS "Using in-tree dependencies")
    add_subdirectory(../extism/libextism extism)
    add_subdirectory(../jsoncpp jsoncpp)
else()
    include(FetchContent)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)

    # extism
    find_package(extism)
    if(NOT extism_FOUND)
        message(STATUS "Fetching extism via FetchContent")
        FetchContent_Declare(
                extism
                GIT_REPOSITORY https://github.com/extism/extism.git
                GIT_TAG main
                SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/extism
                SOURCE_SUBDIR libextism
        )
        FetchContent_MakeAvailable(extism)
        if(MSVC)
            # Patch for /defaultlib:msvcrt
            get_target_property(existing_libs extism-static INTERFACE_LINK_LIBRARIES)
            set(filtered_libs "")
            foreach(lib IN LISTS existing_libs)
                if(lib STREQUAL "/defaultlib:msvcrt")
                    list(APPEND filtered_libs "$<$<CONFIG:Debug>:msvcrtd>$<$<NOT:$<CONFIG:Debug>>:msvcrt>")
                else()
                    list(APPEND filtered_libs "${lib}")
                endif()
            endforeach()
            set_target_properties(extism-static PROPERTIES INTERFACE_LINK_LIBRARIES "${filtered_libs}")
        endif()
    endif()

    # jsoncpp
    find_package(jsoncpp)
    if(NOT jsoncpp_FOUND)
        message(STATUS "Fetching jsoncpp via FetchContent")
        FetchContent_Declare(
                jsoncpp
                GIT_REPOSITORY https://github.com/open-source-parsers/jsoncpp.git
                GIT_TAG master
                SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/jsoncpp
        )
        FetchContent_MakeAvailable(jsoncpp)
    endif()
endif()

# === Library ===
add_library(extism-cpp STATIC)
target_sources(extism-cpp PRIVATE ${extism_cpp_sources})
target_compile_features(extism-cpp PUBLIC cxx_std_17)
target_include_directories(extism-cpp PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
)
target_link_libraries(extism-cpp
        PUBLIC extism-static
        PRIVATE jsoncpp_lib
)
set_target_properties(extism-cpp PROPERTIES
        VERSION ${PROJECT_VERSION}
        PUBLIC_HEADER src/extism.hpp
        NO_SONAME 1
)

# === Pkg-config ===
configure_file(extism-cpp.pc.in extism-cpp.pc @ONLY)

# === Install ===
include(GNUInstallDirs)

install(TARGETS extism-cpp EXPORT extism-cpp
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/extism-cpp.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)

if (EXTISM_CPP_WITH_CMAKE_PACKAGE)
    include(CMakePackageConfigHelpers)

    configure_package_config_file(
            extism-cppConfig.cmake.in
            ${CMAKE_CURRENT_BINARY_DIR}/extism-cppConfig.cmake
            INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/extism-cpp
    )

    write_basic_package_version_file(
            ${CMAKE_CURRENT_BINARY_DIR}/extism-cppConfigVersion.cmake
            VERSION ${PROJECT_VERSION}
            COMPATIBILITY SameMajorVersion
    )

    install(EXPORT extism-cpp
            FILE extism-cpp-targets.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/extism-cpp
    )

    install(FILES
            ${CMAKE_CURRENT_BINARY_DIR}/extism-cppConfig.cmake
            ${CMAKE_CURRENT_BINARY_DIR}/extism-cppConfigVersion.cmake
            ${CMAKE_CURRENT_SOURCE_DIR}/extism-cpp-namespaced-targets.cmake
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Findextism.cmake
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/Findjsoncpp.cmake
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/extism-cpp
    )
endif()

# === Tests ===
find_package(GTest)
if(GTest_FOUND)
    enable_testing()
    add_executable(extism-test test/test.cpp)
    target_link_libraries(extism-test GTest::gtest extism-cpp)
    include(GoogleTest)
    add_test(NAME Test COMMAND extism-test)
endif()
