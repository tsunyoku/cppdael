#include <pybind11/pybind11.h>
#include <iostream>
#include "rijndael.h"

std::string decrypt(std::string buffer, std::string key, std::string iv)
{
    return decrypt_string(buffer, key, iv); // this probably doesn't need to be standalone
}

PYBIND11_MODULE(cppdael, handle) {
    handle.doc() = "Python wrapper around a C++ Rijndael implementation.";
    handle.def("decrypt", &decrypt);
}
