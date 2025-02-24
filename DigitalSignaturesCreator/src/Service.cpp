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

bool Service::getInitFlagPriKey()
{
    return this->flagInitPrivate;
}

bool Service::getInitFlagPubKey()
{
    return this->flagInitPublic;
}

Status Service::verifyIfFile(const std::string &path)
{
    std::filesystem::path path_fs = std::filesystem::absolute(path);
    if(std::filesystem::exists(path_fs) && std::filesystem::is_regular_file(path_fs))
    {
        return Status::SUCCESS;
    }
    return Status::FAILURE;
}

std::vector<unsigned char> Service::readFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    return std::vector<unsigned char>(std::istreambuf_iterator<char>(file), {});
}

static int passwordCallback(char* buf, int size, int rwflag, void* userdata) {
    Service* service = static_cast<Service*>(userdata);
    int sz = 0;
    std::string password;
    if(service->hasPasswd())
    {
        // it has a password
        // need to prompt for password
        std::cout << "Enter the password:\n";
        std::cin >> password;
        if(std::cin.eof())
            password = "_";

#ifndef _MSC_VER 
        memcpy(buf, password.data(), password.size());
#endif
        sz = password.size();
    
    }
    else
    {
        buf = nullptr;
    }
    return sz;
}

Status Service::digitalSignDocument(const std::string &filename)
{
    std::filesystem::path path_ = std::filesystem::absolute(filename);
    const EVP_MD* hashAlgo = nullptr;
    if(this->m_type == Hash::SHA_256)
    {
        hashAlgo = EVP_sha256();
    }
    else if(this->m_type == Hash::SHA_512)
    {
        hashAlgo = EVP_sha512();
    }  
    
    std::unique_ptr<BIO, std::function<void(BIO*)>> bio(BIO_new_file(std::filesystem::absolute(this->m_pathToPriKey).string().c_str(), "r") , this->customDeleter_BIO);
    if(bio.get() == nullptr)
    {
        std::cout << "Cannot create a bio from a file\n";
        return Status::FAILURE;
    }

    std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> key(nullptr, this->customDeleter_EVP_PKEY);

    EVP_PKEY* k = key.get();    
    k = PEM_read_bio_PrivateKey(bio.get(), nullptr, passwordCallback, reinterpret_cast<void*>(this));

    bool needPassword = false;
    if(k == nullptr)
    {
        needPassword = true;
    }
    else
    {
        std::cout << "Got the key!!!\n";
    }
    std::string password;
    do
    {
        if(needPassword)
        {
            std::cout << "Need a password:\n";
            std::cin >> password;
            if(std::cin.eof())
            {
                password = "_";
            }
            if(password == "_")
            {
                return Status::FAILURE;
            }
            else
            {
                //  means we read password. If password is right, we can extract a key
                k = PEM_read_bio_PrivateKey(bio.get(), nullptr, passwordCallback, reinterpret_cast<void*>(this));
                if(k != nullptr)
                {
                    std::cout << "Extracted the key successfully\n";
                    break;
                }
                else
                {
                    std::cout << "Wrong password\n";
                }
            }
        }
        else 
        {
            break;
        }
    }
    while(true);
    //so, we get the keys inside a PKEY unique_ptr
    std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> ctx(EVP_MD_CTX_new(), this->customDeleter_EVP_MD_CTX);
    if(ctx.get() == nullptr)
    {
        std::cout << "Cannot init a md ctx for hashing\n";
        return Status::FAILURE;
    }
    key.reset(k);
    if(EVP_DigestSignInit(ctx.get(), nullptr, hashAlgo, nullptr, key.get()) <= 0)
    {
        std::cout << "Error init and ctx for hashing with key\n";
        return Status::FAILURE;
    }
    std::ifstream file(path_, std::ios::binary);
    if(!file)
    {
        std::cout << "Cannot open the file\n";
        return Status::FAILURE;    
    }

    const size_t bufferSize = 4096;  
    std::vector<unsigned char> buffer(bufferSize);
    while (file) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        size_t bytesRead = file.gcount();
        if (bytesRead > 0) {
            // Update the signing context with the chunk
            if (EVP_DigestSignUpdate(ctx.get(), buffer.data(), bytesRead) <= 0) {
                std::cout << "Cannot update dgst ctx\n";
            }
        }
    }
    size_t signatureLen = 0;
    if (EVP_DigestSignFinal(ctx.get(), nullptr, &signatureLen) <= 0) {
        std::cout << "Failed to finalize the signature length\n";
        return Status::FAILURE;
    }
    std::vector<unsigned char> signature(signatureLen);
    if (EVP_DigestSignFinal(ctx.get(), signature.data(), &signatureLen) <= 0) {
        std::cout << "Failed to generate the signature";
        return Status::FAILURE;
    }
    // writing a digital signature into the file
    writeSignatureIntoFile(path_, signature);
    return Status::SUCCESS;
}

void Service::writeSignatureIntoFile(const std::string &path, std::vector<unsigned char> &signature)
{
    std::filesystem::path path_ = std::filesystem::absolute(path);
    std::filesystem::path pathForCreation = path_.parent_path();
    std::string fileName = std::string(path_.filename().string()) + ((this->m_sign == Sign::RSA) ? "_rsa.bin" : "_ecdsa.bin");
    if(pathForCreation.empty())
    {
        pathForCreation = path_.root_path();
    }
    pathForCreation = pathForCreation / fileName;
    std::ofstream signatureFileStream(pathForCreation, std::ios::binary);
    if (!signatureFileStream) {
        std::cout << "Cannot write a file\n";
        return;
    }
    signatureFileStream.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    if (!signatureFileStream) {
        std::cout << "Cannot write a file2\n";
    }
}


bool Service::hasPasswd() const
{
    if(this->m_passwd == Passwd::YES)
        return true;
    return false;
}

std::optional<std::vector<unsigned char>> Service::getHashOfDocumentByPath(const std::string& path)
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
    if(this->m_type == Hash::SHA_256)
    {
        hashAlgo = EVP_sha256();
    }
    else if(this->m_type == Hash::SHA_512)
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


void Service::writeHashIntoFile(const std::string &path, std::vector<unsigned char> &hash)
{
    std::filesystem::path path_ = std::filesystem::absolute(path);
    std::filesystem::path pathForCreation = path_.parent_path();
    std::string fileName = std::string(path_.filename().string()) + ((this->m_type == Hash::SHA_256) ? ".sha256" : ".sha512");
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
    if(this->m_type == Hash::SHA_256)
    {
        fileToWrite << "SHA2-256(" << path_.filename().string() << ")= ";
    }
    else if(this->m_type == Hash::SHA_512)
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
                    this->flagInitPrivate = true;
                    this->flagInitPublic = true;
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
