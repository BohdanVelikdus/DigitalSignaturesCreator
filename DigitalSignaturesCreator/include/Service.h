#pragma once 

#include <string>
#include <functional>
#include <memory>
#include <optional>
#include <iostream>
#include <fstream>
#include <filesystem>

#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/evperr.h"
#include "openssl/encoder.h"
#include "openssl/bio.h"

enum class Hash
{
    SHA_256,
    SHA_512
};

enum class Status
{
    SUCCESS,
    FAILURE
};

enum class CertState
{
    NEW,
    CUSTOM,
    PRESET
};

enum class Sign
{
    ECDSA, 
    RSA
};

enum class Passwd
{
    YES,
    NO
};


inline void printFinalMessage()
{
    std::cout << "\nThank you, have a nice day\n";
}


inline std::string getInputFromConsoleNum()
{
    std::string input = "0";
    if(!std::cin.eof())
    {
        std::cin >> input;
    }
    return input;
}

inline std::string getInputFromConsoleString()
{
    std::string input;
    std::cin >> input;
    if(std::cin.eof())
        input = "_";
    return input;
}

inline Status verifyIfFolder(std::string path)
{
    std::filesystem::path path_ = std::filesystem::absolute(path);
    if(std::filesystem::exists(path_) && std::filesystem::is_directory(path_))
    {
        return Status::SUCCESS;
    }
    else
    {
        return Status::FAILURE;
    }
}

inline Status verifyIfFile(const std::string &path)
{
    std::filesystem::path path_fs = std::filesystem::absolute(path);
    if(std::filesystem::exists(path_fs) && std::filesystem::is_regular_file(path_fs))
    {
        return Status::SUCCESS;
    }
    return Status::FAILURE;
}

inline std::vector<unsigned char> readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(file), {});
}