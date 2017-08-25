AES in C (WIP)
==============

This is an implementation of the Advanced Encryption Standard (AES) written in portable C99.

It currently supports ECB mode AES-128 encryption and decryption, verified with the test cases in the [NIST AES Algorithm Validation Suite's](http://csrc.nist.gov/groups/STM/cavp/documents/aes/AESAVS.pdf) Known Answer Test.

Tested with the **GCC 7.1.0** and **Clang 4.0.1** compilers on **x86_64 GNU/Linux**.


Dependencies
------------

Toolchain:

- C99 compiler
- [Meson](http://mesonbuild.com)


Build instructions
------------------

This project uses the [Meson build system](http://mesonbuild.com).

Change to the project root directory:

    cd aes

Set up the build directory, change to the build directory, and build with Ninja:

    meson build && cd build && ninja

This will produce a ``libaes.so`` shared library and an ``aes-test`` executable.


Running the test suite
----------------------

Run the tests with Ninja:

    ninja test

Alternatively, run the test executable directly:

    ./aes-test
