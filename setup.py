import platform
import sys
from setuptools import setup, Extension

with open("README.md", "r") as fh:
    long_description = fh.read()

extra_compile_args = []
if sys.platform != "win32":
    extra_compile_args.append("-std=c++2a")
if platform.machine() == "aarch64":
    extra_compile_args.append("-fsigned-char")

setup(
    name="cppdael",
    description="A wrapper for Rijndael",
    author="tsunyoku",
    version="0.0.1",
    keywords=["python", "cpython", "rijndael", "aes", "encryption"],
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
    ],
    url="https://github.com/tsunyoku/cppdael",
    download_url="https://github.com/tsunyoku/cppdael/tarball/master",
    long_description=long_description,
    long_description_content_type="text/markdown",
    ext_modules=[
        Extension(
            "cppdael",
            ["extension.cpp", "rijndael.cpp"],
            language="c++",
            extra_compile_args=extra_compile_args,
        )
    ],
)
