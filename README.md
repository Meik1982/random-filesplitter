# random-filesplitter (rfs)

A small tool that splits a file into two separate files for encryption purposes. Both generated files are required to restore the original file.

## Features
* Splits any given file into two parts.
* Increases security by requiring both parts to reconstruct the original data.
* Lightweight and fast C++ implementation.

## How to Compile
You can easily compile the source code using standard C++ compilers like GCC:

`g++ rfs.cpp -o rfs`

## License
This project is licensed under the GNU Lesser General Public License v2.1 (LGPL-2.1). See the `LICENSE` file for details.
