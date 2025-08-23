cmake_minimum_required(VERSION 3.30...3.34)

# Set project and app name
set(APP_NAME chatServer)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(${APP_NAME} VERSION 1.0 LANGUAGES CXX)

if (WIN32 OR MSVC)
    message(FATAL_ERROR "❌ ${APP_NAME} only supports Linux/GCC/Clang. Windows/MSVC is not supported.")
endif()

# Require modern C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ---- Dependency: Quill ----
# First try system-installed Quill
find_package(Quill QUIET)
find_package(CLI11 CONFIG)

if (NOT Quill_FOUND)
    message(STATUS "Quill not found on system, fetching with FetchContent...")

    include(FetchContent)
    FetchContent_Declare(
        quill
        GIT_REPOSITORY https://github.com/odygrd/quill.git
    )
    FetchContent_MakeAvailable(quill)
endif()

if (NOT CLI11_FOUND)

    include(FetchContent)
    FetchContent_Declare(
        cli11_proj
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG v2.5.0
)
    FetchContent_MakeAvailable(cli11_proj)
endif()
# ---- App ----
add_executable(${APP_NAME} main.cpp)
target_link_libraries(${APP_NAME} PRIVATE CLI11::CLI11)
target_link_libraries(${APP_NAME} PRIVATE quill::quill)
target_include_directories(${APP_NAME} PRIVATE ${CMAKE_SOURCE_DIR})

# Enable warnings
target_compile_options(${APP_NAME} PRIVATE -Wall -Wextra -Wpedantic)

# Default build type = Debug (if none set)
if (NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Debug CACHE STRING
        "Choose the type of build (Debug or Release)" FORCE)
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE
    $<$<CONFIG:Debug>:DEBUG_BUILD>     # custom debug flag
    $<$<CONFIG:Release>:NDEBUG>        # force NDEBUG in Release
)
# Debug vs Release flags
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")
