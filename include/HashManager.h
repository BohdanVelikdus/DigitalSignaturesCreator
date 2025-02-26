#pragma once

#include <functional>

#include "Service.h"
#include "CertificateManager.h"

class HashManager
{
public:
    HashManager() : m_algorithm(Hash::SHA_256){}

    void setCallbackChangingHash(std::function<void(Hash)> callback);

    std::optional<std::vector<unsigned char>> getHashOfDocumentByPath(const std::string& path);

    void writeHashIntoFile(const std::string& path, std::vector<unsigned char>& hash);

    std::string getHashType();

    Status setHashType(std::string nameOfType);

    Status configureHash();

private:

    Hash m_algorithm;

    // callback for changing hash in Certificate manager
    std::function<void(Hash)> m_callbackChangeHash;

    std::function<void(EVP_MD_CTX*)> customDeleter_EVP_MD_CTX = [](EVP_MD_CTX *ptr){if(ptr){EVP_MD_CTX_free(ptr);}};

};