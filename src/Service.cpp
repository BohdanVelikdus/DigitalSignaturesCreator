#include "Service.h"

#include <iostream>
#include <string>
#include <exception>
#include <stdexcept>
#include <filesystem>
#include <fstream>

#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/ec.h"
#include "openssl/err.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "openssl/evperr.h"
#include "openssl/encoder.h"
#include "openssl/bio.h"

Service::Service()
{
    this->m_type = Hash::SHA_512;

}

std::string Service::getHashType()
{
    switch (m_type)
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

Status Service::setHashType(std::string nameOfType)
{
    if(nameOfType == "sha_256" || nameOfType == "sha-256")
    {
        m_type = Hash::SHA_256;
        return Status::SUCCESS;
    }
    else if(nameOfType == "sha_512" || nameOfType == "sha-512")
    {
        m_type = Hash::SHA_512;
        return Status::SUCCESS;
    }
    else
    {
        return Status::FAILURE;
    }
}

Status Service::verifyIfFolder(std::string path)
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

void Service::setState(CertState state)
{
    this->m_state = state;
}

void Service::clearAllPaths()
{
    m_pathToNewCertFolder.clear();
    m_pathToPriKey.clear();
    m_pathToPubKey.clear();
}

void Service::setPathToNewCertFolder(std::string path)
{
    this->m_pathToNewCertFolder = path;
}

void Service::setSign(Sign sign)
{
    this->m_sign = sign;
}

void Service::setPasswd(Passwd passwd)
{
    this->m_passwd = passwd;
}

Status Service::CreateCert()
{
    // creatng a cerificate to the responding needs
    bool fl = true;
    do
    {
        std::cout << "Enter the name of certificate\n";
        std::string inputFromConsole;
        std::cin >> inputFromConsole;
        if(std::cin.eof())
            inputFromConsole = "_";

        if(inputFromConsole == "_")
        {
            this->signalFlag = true;
            return Status::FAILURE;
        }
        else
        {
            // have to verify if the name exist and available
            std::string tempPRIname;
            std::string tempPUBname;
            if(m_passwd == Passwd::NO)
            {
                tempPRIname = this->m_pathToNewCertFolder + "/" + inputFromConsole + "_pri.pem";
                tempPUBname = this->m_pathToNewCertFolder + "/" + inputFromConsole + "_pub.pem";
            }    
            else
            {
                tempPRIname = this->m_pathToNewCertFolder + "/" + inputFromConsole + "_pri.enc.pem";
                tempPUBname = this->m_pathToNewCertFolder + "/" + inputFromConsole + "_pub.enc.pem";
            }
            std::filesystem::path pathPRI(tempPRIname);
            std::filesystem::path pathPUB(tempPUBname);
            this->m_pathToPriKey = tempPRIname;
            this->m_pathToPubKey = tempPUBname;

            if(std::filesystem::exists(pathPRI) || std::filesystem::exists(pathPUB))
            {
                std::cout << "The files exists, enter other name\n";
            }
            else
            {
                // means the file does not exists, can create our files
                std::fstream filePRI(pathPRI, /*std::ios::binary |*/ std::ios::out);
                std::fstream filePUB(pathPUB, /*std::ios::binary |*/ std::ios::out);
                Status status = Status::FAILURE;

                if(this->m_sign == Sign::RSA)
                {
                    status = createRSACert(filePRI, filePUB);
                }
                else if(this->m_sign == Sign::ECDSA)
                {
                    status = createECDDSACert(filePRI, filePUB);
                }
                if(status == Status::FAILURE)
                {
                    // means we have to delete the file we created
                    filePRI.close();
                    if (!std::filesystem::remove(pathPRI)) {
                        std::cerr << "Failed to delete " << pathPRI << std::endl;
                    }
                    filePUB.close();
                    if (!std::filesystem::remove(pathPUB)) {
                        std::cerr << "Failed to delete " << pathPUB << std::endl;
                    }
                }
                else 
                {
                    this->flagInit = true;
                }
                return status;
            }
        }
    }while(fl);
    return Status::FAILURE;
}

void handleError()
{
    unsigned long error_code = ERR_get_error();
    if (error_code != 0)
    {
        char error_string[120];
        ERR_error_string_n(error_code, error_string, sizeof(error_string));
        std::cerr << "OpenSSL Error: " << error_string << std::endl;
    }
}

bool Service::getInitFlag()
{
    return this->flagInit;
}

Status Service::WriteCertToFiles(std::fstream &filePRI, std::fstream &filePUB, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY *)>> &&keyPair, Sign certType)
{
    // Private Key Encoding
    std::unique_ptr<char[]> propq(nullptr);                                                                                                                            
    std::unique_ptr<OSSL_ENCODER_CTX, std::function<void(OSSL_ENCODER_CTX*)>> E_ctx(OSSL_ENCODER_CTX_new_for_pkey(keyPair.get(), OSSL_KEYMGMT_SELECT_PRIVATE_KEY, "PEM", (certType == Sign::RSA)?"PKCS1":nullptr, propq.get()), this->customDeleter_OSSL_ENCODER_CTX);

    if(E_ctx.get() == nullptr)
    {
        std::cout << "Error with creating E_ctx\n";
        return Status::FAILURE;
    }

    std::string inputPassword;
    if(this->m_passwd == Passwd::YES)
    {
        // Ask for a password to encrypt the private key
        std::cout << "Enter the password to encrypt the private key: ";
        std::cin >> inputPassword;

        if(std::cin.eof() || inputPassword.empty())
        {
            std::cout << "Invalid password input\n";
            return Status::FAILURE;
        }

        //test
        if(OSSL_ENCODER_CTX_set_cipher(E_ctx.get(), "AES-256-CBC", propq.get()) == 0)
        {
            std::cout << "Error with seting cipher\n";
            return Status::FAILURE;
        }
        // Set the passphrase to encrypt the private key
        OSSL_ENCODER_CTX_set_passphrase(E_ctx.get(), reinterpret_cast<const unsigned char*>(inputPassword.c_str()), inputPassword.size());
    }

    unsigned char *privateKeyData = nullptr;
    size_t privateKeyLen = 0;

    // Encode the private key into a data buffer
    if (OSSL_ENCODER_to_data(E_ctx.get(), &privateKeyData, &privateKeyLen) != 1)
    {
        std::cout << "Error with encoding private key to data\n";
        return Status::FAILURE;
    }

    // Writing private key data to file
    filePRI.write(reinterpret_cast<const char*>(privateKeyData), privateKeyLen);
    filePRI.close();

    // Free allocated memory
    OPENSSL_free(privateKeyData);
    
    // Public Key Encoding
    E_ctx.reset(OSSL_ENCODER_CTX_new_for_pkey(keyPair.get(), OSSL_KEYMGMT_SELECT_PUBLIC_KEY, "PEM",  (certType == Sign::RSA)?"PKCS1":nullptr, nullptr));

    if(!E_ctx.get())
    {
        std::cout << "Error with E_ctx for public key\n";
        return Status::FAILURE;
    }

    unsigned char *publicKeyData = nullptr; 
    size_t publicKeyLen = 0;

    // Encode the public key into a data buffer
    if (OSSL_ENCODER_to_data(E_ctx.get(), &publicKeyData, &publicKeyLen) != 1)
    {
        std::cout << "Error with encoding public key to data\n";
        return Status::FAILURE;
    }

    // Writing public key data to file
    filePUB.write(reinterpret_cast<const char*>(publicKeyData), publicKeyLen);
    filePUB.close();

    // Free allocated memory
    OPENSSL_free(publicKeyData);
    
    // If all is ok, return success
    //return Status::SUCCESS;

    return Status::SUCCESS;
}

Status Service::createRSACert(std::fstream &filePRI, std::fstream &filePUB)
{
    // the last nullptr for engine
    std::unique_ptr<EVP_PKEY_CTX, std::function<void(EVP_PKEY_CTX*)>> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), this->customDeleter_EVP_PKEY_CTX);
    if(ctx.get() == nullptr)
    {
        std::cout << "Error with EVP_PKEY_CTX_new_id\n";
        return Status::FAILURE;
    }
    if(EVP_PKEY_keygen_init(ctx.get()) <= 0)
    {
        std::cout << "Error with initializing a keygen context\n";
        return Status::FAILURE;
    }
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 4096) <= 0)
    {
        std::cout << "Cannot set the keygen bits in rsa\n";
        return Status::FAILURE;
    }
    std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> keyPair(nullptr, this->customDeleter_EVP_PKEY);
    EVP_PKEY* k = keyPair.get();
    if(EVP_PKEY_keygen(ctx.get(), &k) <= 0)
    {
        std::cout << "Error with generating key pair\n";
        return Status::FAILURE;
    }
    keyPair.reset(k);
    return WriteCertToFiles(filePRI, filePUB, std::move(keyPair), Sign::RSA);
}


Status Service::createECDDSACert(std::fstream& filePRI, std::fstream& filePUB)
{
    // ec stands for eliptic curve
    std::unique_ptr<EVP_PKEY_CTX, std::function<void(EVP_PKEY_CTX*)>> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), this->customDeleter_EVP_PKEY_CTX);
    if(ctx.get() == nullptr)
    {
        std::cout << "Unable to create a EVP_PKEY_CTX for ecdsa\n";
        return Status::FAILURE; 
    }
    if(EVP_PKEY_keygen_init(ctx.get()) <= 0)
    {
        std::cout << "Unable to init a ctx for generating a key\n";
        return Status::FAILURE;
    }
    if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime239v3) <= 0)
    {
        std::cout << "Cannot set this type of curve\n";
        return Status::FAILURE;
    }
    std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> keyPair(nullptr, this->customDeleter_EVP_PKEY);
    EVP_PKEY* k = keyPair.get();
    if(EVP_PKEY_generate(ctx.get(), &k) <= 0)
    {
        std::cout << "Error with generating a key\n";
        return Status::FAILURE;
    }
    keyPair.reset(k);
    // now we have a key-pair in the EVP_PKEY
    return WriteCertToFiles(filePRI, filePUB, std::move(keyPair), Sign::ECDSA);
}
