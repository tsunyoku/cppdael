cmake_minimum_required(VERSION 3.4)
project(cppdael)

add_subdirectory(pybind11)
pybind11_add_module(cppdael SHARED bindings.cpp rijndael.cpp)