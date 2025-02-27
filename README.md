# Digital Signature Project 

## Overview 

This project provides a secure digital signature implementation using OpenSSL in C++. It enables:

* RSA key generation 

* Signing documents 

* Verifying signatures 

* Creating hashes and writing them into file

## Built with CMake and Conan for dependency management.

### Build Instructions

#### Install Dependencies

Ensure you have the following installed:

* Conan (for package management)

* CMake (for building the project)

* Python (for setup script)

#### Setup Conan Environment

Run the Python script to initialize Conan:

```python init.py```

This script will install necessary dependencies and configure profiles.

#### Configure & Build

```cmake -DCMAKE_POLICY_DEFAULT_CMP0091=NEW -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -G "Unix Makefiles" ```

### Usage
The tool is cli and has a step-by-instruction to allow interactive and simple usage 

