cmake_minimum_required(VERSION 3.18)
project(symbolize)

set(CMAKE_CXX_STANDARD 17)

add_executable(symbolize main.cpp
        symbolize.cpp
        symbolize.h)
