#include <pybind11/pybind11.h>
#include <iostream>
#include "rijndael.h"

#define ZeroArray(s) memset(s,0,sizeof(s))

namespace py = pybind11;

std::string remove_chars(const std::string str, char* charsToRemove)
{
    char c[str.length()+1];
    const char *p = str.c_str();
    unsigned int z=0, size = str.length();
    unsigned int x;
    bool rem=false;

    for(x=0; x<size; x++)
    {
        rem = false;
        for (unsigned int i = 0; charsToRemove[i] != 0; i++)
        {
            if (charsToRemove[i] == p[x])
            {
                rem = true;
                break;
            }
        }
        if (rem == false) c[z++] = p[x];
    }

    c[z] = '\0';
    return std::string(c);
}

std::string decrypt(std::string buffer, std::string key, std::string iv)
{
    const std::string _result = decrypt_string(buffer, key, iv); // this probably doesn't need to be standalone
    std::string result = remove_chars(_result, (char*)"\x14");

    return result;
}

PYBIND11_MODULE(cppdael, handle) {
    handle.doc() = "Python wrapper around a C++ Rijndael implementation.";
    handle.def("decrypt", &decrypt);
}