#include "HashManager.h"

#include <optional>
#include <fstream>
#include <filesystem>
#include <string>
#include <iostream>

#include "Service.h"

void HashManager::setCallbackChangingHash(std::function<void(Hash)> callback)
{
    this->m_callbackChangeHash = callback;
}

std::optional<std::vector<unsigned char>> HashManager::getHashOfDocumentByPath(const std::string &path)
{
    std::ifstream file(path, std::ios::binary);
    if(!file)
    {
        return std::nullopt;    
    }

    std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> ctx(EVP_MD_CTX_new(), this->customDeleter_EVP_MD_CTX);
    if(ctx.get() == nullptr)
    {
        std::cout << "Error with a initializing a md_ctx\n";
        return std::nullopt;
    }

    const EVP_MD* hashAlgo = nullptr;
    if(this->m_algorithm == Hash::SHA_256)
    {
        hashAlgo = EVP_sha256();
    }
    else if(this->m_algorithm == Hash::SHA_512)
    {
        hashAlgo = EVP_sha512();
    }   
    
    if(EVP_DigestInit_ex(ctx.get(), hashAlgo, nullptr) != 1)
    {
        std::cout << "Cannot set the digest algo\n";
        return std::nullopt;
    }

    std::vector<unsigned char> bufferToReadFromFile(4096);
    while(file.read(reinterpret_cast<char* >(bufferToReadFromFile.data()), bufferToReadFromFile.size()) || file.gcount() > 0)
    {
        if(EVP_DigestUpdate(ctx.get(), bufferToReadFromFile.data(), file.gcount()) != 1)
        {
            std::cout << "Cannot update a context, by appending a data from file";
            return std::nullopt;
        }
    }

    std::vector<unsigned char> hash(EVP_MD_size(hashAlgo));
    unsigned int hash_length = 0;
    if(EVP_DigestFinal_ex(ctx.get(), hash.data(), &hash_length) !=  1)
    {
        std::cout << "Cannot find the sha512 of the file in digestfile_ex\n";
        return std::nullopt;
    }
    else
    {
        return hash;
    }
}


void HashManager::writeHashIntoFile(const std::string &path, std::vector<unsigned char> &hash)
{
    std::filesystem::path path_ = std::filesystem::absolute(path);
    std::filesystem::path pathForCreation = path_.parent_path();
    std::string fileName = std::string(path_.filename().string()) + ((this->m_algorithm == Hash::SHA_256) ? ".sha256" : ".sha512");
    if(pathForCreation.empty())
    {
        pathForCreation = path_.root_path();
        
    }
    pathForCreation = pathForCreation / fileName;
    std::ofstream fileToWrite(pathForCreation);
    if(!fileToWrite)
    {
        std::cout << "Cannot create a file, potentially other users does not have a permissions to write into it\n"
                  << "Or executable does not have permission\n";
        return;
    }
    if(this->m_algorithm == Hash::SHA_256)
    {
        fileToWrite << "SHA2-256(" << path_.filename().string() << ")= ";
    }
    else if(this->m_algorithm == Hash::SHA_512)
    {
        fileToWrite << "SHA2-512(" << path_.filename().string() << ")= ";
    }

    for (unsigned int i = 0; i < hash.size(); i++) {
        fileToWrite << std::hex << /*std::uppercase <<*/ (hash[i] >> 4) << (hash[i] & 0xF);
    }
    fileToWrite.close();
    std::cout << "Hash written to " << pathForCreation.string() << std::endl;
    return ;
}

std::string HashManager::getHashType()
{
    switch (m_algorithm)
    {
    case Hash::SHA_256:
        return "SHA-256";
    case Hash::SHA_512:
        return "SHA-512";
    default:
        throw std::runtime_error("Unexpected hash type");
        return "";
        break;
    }
}

Status HashManager::setHashType(std::string nameOfType)
{
    if(nameOfType == "sha_256" || nameOfType == "sha-256")
    {
        m_algorithm = Hash::SHA_256;
        this->m_callbackChangeHash(Hash::SHA_256);
        return Status::SUCCESS;
    }
    else if(nameOfType == "sha_512" || nameOfType == "sha-512")
    {
        m_algorithm = Hash::SHA_512;
        this->m_callbackChangeHash(Hash::SHA_512);
        return Status::SUCCESS;
    }
    else
    {
        return Status::FAILURE;
    }
}

Status HashManager::configureHash()
{
    Status status = Status::FAILURE;
    std::string input;
    do
    {
        std::cout << "Enter hash algo: SHA-256 or SHA-512:\n";
        input = getInputFromConsoleString();
        std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c){return std::tolower(c);});
        if(input != "_")
        {
            status = setHashType(input);
            if(status == Status::FAILURE)
                std::cout << "Wrong name of hash algo\n";
            else
            {
                std::cout << "The hash type is set successfully!!!\n";
                return Status::SUCCESS;
            }
        }
        else
        {
            printFinalMessage();
            return Status::FAILURE;
            break;
        }
    }
    while(status == Status::FAILURE);
    return Status::FAILURE;
}