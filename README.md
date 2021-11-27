# C++-dael

A pybind11 wrapper for Rijndael decryption.

## What?

As most people know, Python is considerably slower in it's operations compared to other languages, and some things are time critical. We have the ability to run C++ code in Python with the use of libraries such as pybind11 (what this project uses) to utilise C++'s speed at a cost of well- writing bindings. This package is a ready to use module to decrypt Rijndael ciphers in Python with C++ speed.

## Compiling

First make a folder called `build` in the main directory. Go into that directory and run `cmake ..` (you may need to install it first). Once it finishes, run `make`. This will generate a .so file which is our python module. You can move this so file to wherever you would like to use cppdael and import it using `import cppdael`.

Soon, I will upload the bindings onto pypi so it can be installed as a package.

## Usage

Currently, this only has decryption capabilities, as I made this largely with osu! servers in mind. To decrypt something you must call the `decrypt` function which takes the args `buffer: str, key: str, iv: str`. It will return the decoded buffer in the form of a string.

## Testing

There is both a c++ and python example of using these bindings and example.py will also give you the speed differences between python and the bindings. From my testing the python version will average at around 90ms while the c++ bindings will average at 1-2ms.