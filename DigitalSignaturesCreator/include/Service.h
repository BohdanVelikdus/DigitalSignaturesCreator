#pragma once 

#include <string>
#include <functional>
#include <memory>
#include <optional>

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

class Service
{
public:

    Service();

    std::string getHashType();

    Status setHashType(std::string nameOfType);

    Status verifyIfFolder(std::string path);

    void setState(CertState state);

    void clearAllPaths();

    void setPathToNewCertFolder(std::string path);

    void setSign(Sign sign);

    void setPasswd(Passwd status);

    Status CreateCert();

    // check if the ctrl+c or ctrl+d is pressed
    bool signalFlag = false;

    bool getInitFlag();

    Status verifyIfFile(const std::string& path);

    std::optional<std::vector<unsigned char>> getHashOfDocumentByPath(const std::string& path);

    void writeHashIntoFile(const std::string& path, std::vector<unsigned char>& hash);

    std::vector<unsigned char> readFile(const std::string& filename);

    Status digitalSignDocument(const std::string& filename);

    bool hasPasswd() const;

    void writeSignatureIntoFile(const std::string &path, std::vector<unsigned char> &signature);

private:

    Status WriteCertToFiles(std::fstream& filePRI, std::fstream& filePUB, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> &&keyPair,Sign certType);

    Status createRSACert(std::fstream& filePRI, std::fstream& filePUB);

    Status createECDDSACert(std::fstream& filePRI, std::fstream& filePUB);

    Hash m_type;
    CertState m_state;
    Sign m_sign;
    Passwd m_passwd;

    bool flagInit = false;

    std::string m_pathToNewCertFolder = "";
    std::string m_pathToPriKey = "";
    std::string m_pathToPubKey = "";

    std::function<void(EVP_PKEY*)> customDeleter_EVP_PKEY = [](EVP_PKEY *ptr){if(ptr){EVP_PKEY_free(ptr);}};
    std::function<void(EVP_PKEY_CTX*)> customDeleter_EVP_PKEY_CTX = [](EVP_PKEY_CTX *ptr){if(ptr){EVP_PKEY_CTX_free(ptr);}};
    std::function<void(OSSL_ENCODER_CTX*)> customDeleter_OSSL_ENCODER_CTX = [](OSSL_ENCODER_CTX *ptr){if(ptr){OSSL_ENCODER_CTX_free(ptr);}};
    std::function<void(BIO*)> customDeleter_BIO = [](BIO* ptr){if(ptr){BIO_free(ptr);}};
    std::function<void(unsigned char*)> customDeleter_unsigned_char = [](unsigned char* ptr){if(ptr){OPENSSL_free(ptr);}};
    std::function<void(EVP_MD_CTX*)> customDeleter_EVP_MD_CTX = [](EVP_MD_CTX *ptr){if(ptr){EVP_MD_CTX_free(ptr);}};


};