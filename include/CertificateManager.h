#pragma once

#include "Service.h"

#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/evperr.h"
#include "openssl/encoder.h"
#include "openssl/bio.h"

#include <utility>

class CertificateManager
{
public:

    CertificateManager(bool &status);

    void setAlgorithmChange(Hash newAlgo);

    bool getInitFlagPriKey();

    bool getInitFlagPubKey();

    // function for creating a cert
    bool signalFlag = false;

    // adding a certificate routines
    void configureCertificatePrivateKey();

    // creates a public key
    Status createNewCertificatePrivateKey();

    Status chooseAlgoSigning();

    Status chooseIfEncrypted();

    Status CreateCert();
    // end of creating private key

    // adds a public key
    Status manualAddPrivateKey();

    Status verifyValidPrivateKey(const std::string& path);
    // end of adding private key

    // signing routines 
    std::pair<Status, std::vector<unsigned char>> digitalSignDocument(const std::string &filename);

    void writeSignatureIntoFile(const std::string &path, std::vector<unsigned char> &signature);
    //end signing routines

    // adding a public key routines
    void configureCertificatePublicKey();

    Status verifyValidPublicKey(const std::string& path);
    // end a public key routines

    //verifying digital sign routines
    bool verifyDigitalSign(const std::string& pathToFile, const std::string& pathToSignature);
    // end a verifying routines

    bool &status_running;

#ifdef DEBUG
    std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> public_createRSACert(Passwd passwd, Hash hash, Sign sign);
    std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> public_createECDSACert(Passwd passwd, Hash hash, Sign sign);
#endif


private:

    std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> extractPrivateKey();

    std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> createECDSACert();

    std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> createRSACert();

    std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> WriteCertToFiles(std::fstream &filePRI, std::fstream &filePUB, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY *)>> &&keyPair, Sign certType);
    

    Hash m_algorithm;
    Sign m_signClassType;
    Passwd m_passwdRequired;

    bool flagInitPrivate = false;
    std::string m_pathToPriKey = "";

    bool flagInitPublic = false;
    std::string m_pathToPubKey = "";

    std::function<void(EVP_PKEY*)> customDeleter_EVP_PKEY = [](EVP_PKEY *ptr){if(ptr){EVP_PKEY_free(ptr);}};
    std::function<void(EVP_PKEY_CTX*)> customDeleter_EVP_PKEY_CTX = [](EVP_PKEY_CTX *ptr){if(ptr){EVP_PKEY_CTX_free(ptr);}};
    std::function<void(OSSL_ENCODER_CTX*)> customDeleter_OSSL_ENCODER_CTX = [](OSSL_ENCODER_CTX *ptr){if(ptr){OSSL_ENCODER_CTX_free(ptr);}};
    std::function<void(BIO*)> customDeleter_BIO = [](BIO* ptr){if(ptr){BIO_free(ptr);}};
    std::function<void(unsigned char*)> customDeleter_unsigned_char = [](unsigned char* ptr){if(ptr){OPENSSL_free(ptr);}};
    std::function<void(EVP_MD_CTX*)> customDeleter_EVP_MD_CTX = [](EVP_MD_CTX *ptr){if(ptr){EVP_MD_CTX_free(ptr);}};
    std::function<void(X509*)> customDeleter_X509 = [](X509* ptr){if(ptr){X509_free(ptr);}};

};