cmake_minimum_required(VERSION 3.20)
project(nosy VERSION 1.0 LANGUAGES CXX)

# C++ standard to C++20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # lets emacs/clangd find headers

find_package(PcapPlusPlus REQUIRED)

# include headers in dir
include_directories(include)

# executable and soucre files
add_executable(nosy
  src/main.cpp
  src/parser.cpp
)
target_compile_options(nosy PRIVATE -Wall -Wextra)
target_link_libraries(nosy PRIVATE PcapPlusPlus::Pcap++)
