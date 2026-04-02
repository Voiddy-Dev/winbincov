cmake_minimum_required(VERSION 3.10.0)
project(winbincov VERSION 0.1.0 LANGUAGES C CXX)

# --- NEW: FIX UNICODE ERROR ---
if(MSVC)
    add_compile_options(/utf-8)
endif()
# ------------------------------

# --- NEW: MODERN C++ STANDARDS (From previous step) ---
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. TELL CMAKE WHERE TO FIND HEADERS
include_directories(${CMAKE_SOURCE_DIR}/include)

# 2. TELL CMAKE WHERE TO FIND .LIB FILES
link_directories(${CMAKE_SOURCE_DIR}/lib)

# Set common source files and libraries to reduce duplication.
set(COMMON_SOURCES
    Debugger.cpp Debugger.h
)

# Added spdlog.lib here. 
# Because we added 'link_directories' above, it will look inside your 'lib' folder to find it.
set(COMMON_LIBS
    ole32.lib
    dbgeng.lib
    Psapi.lib
    Shell32.lib
    spdlog.lib
)

add_executable(winbincov main.cpp ${COMMON_SOURCES})
target_link_libraries(winbincov PRIVATE ${COMMON_LIBS})