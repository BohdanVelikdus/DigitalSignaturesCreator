#include "CertificateManager.h"

#include "Service.h"

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

#include <utility>

CertificateManager::CertificateManager(bool &status) : status_running(status)
{
    
}

void CertificateManager::setAlgorithmChange(Hash newAlgo)
{
    this->m_algorithm = newAlgo;
}

bool CertificateManager::getInitFlagPriKey()
{
    return this->flagInitPrivate;
}

bool CertificateManager::getInitFlagPubKey()
{
    return this->flagInitPublic;
}

Status CertificateManager::createNewCertificatePrivateKey()
{
    Status status = Status::FAILURE;
    std::optional<std::string> input;
    std::string val;
    while(status == Status::FAILURE && status_running)
    {
        std::cout << "Enter the path to place where cert will be stored\n";
        input = getInputFromConsoleString();
        if(!input.has_value())
        {
            printFinalMessage();
            this->status_running = false;
            return Status::FAILURE;
        }
        else 
        {
            val = input.value();
        }

        if(input == "#")
        {
            return Status::FAILURE;
        }
        else
        {
            status = verifyIfFolder(val);
            if(status == Status::FAILURE)
            {
                std::cout << "The entered path is not a folder\n";
                continue;
            }
            std::cout << "Path OK\n";
            m_pathToPriKey = val;
            m_pathToPubKey = val;
            status = chooseAlgoSigning();
            if(status == Status::FAILURE)
            {
                continue;
            }
            status = chooseIfEncrypted();
            if(status == Status::FAILURE)
            {
                continue;
            }
            status = CreateCert();
            if(status == Status::FAILURE)
            {
                continue;
            }
            return Status::SUCCESS;
        }
    }
    return Status::FAILURE;
}

void CertificateManager::configureCertificatePrivateKey()
{
    Status status = Status::FAILURE;
    std::optional<std::string> inputFromConsole;
    std::string val;
    do
    {   
        std::cout << "\n================\n"
                  << "This program only supports signing using ECDSA or RSA.\n" 
                  << "So you must choose:\n"
                  << "\tNEW to create a new pri and public key in pecified path\n"
                  << "\tMANUAL to manual write the path to private and public key\n";
        inputFromConsole = getInputFromConsoleString();
        if(!inputFromConsole.has_value())
        {
            printFinalMessage();
            this->status_running = false;
            return;
        }
        else 
        {
            val = inputFromConsole.value();
        }

        std::transform(val.begin(), val.end(), val.begin(), [](unsigned char c){return std::tolower(c);});
        if(inputFromConsole == "new")
        {
            // now call the function
            status = createNewCertificatePrivateKey();
            if(status == Status::FAILURE)
            {
                std::cout << "Unexpected error happend, cannot create a certificate with specified options, try other options\n";
            }
            else 
            {
                std::cout << "Certificate created!!!\n";
            }
        }
        else if(inputFromConsole == "manual")
        {
            status = manualAddPrivateKey();
            if(status == Status::FAILURE)
            {
                std::cout << "Unexpected error happend, cannot create a certificate with specified options, try other options\n";
            }
            else 
            {
                std::cout << "Certificate created!!!\n";
            }
        }
        else if(inputFromConsole == "#")
        {
            continue;
        }
        else
        {
            std::cout << "Wrong option.....\n"; 
        }
    } while (status == Status::FAILURE && this->status_running);
}

Status CertificateManager::chooseAlgoSigning()
{
    Status status = Status::FAILURE;
    std::optional<std::string> input;
    std::string inputFromConsole;
    while(status == Status::FAILURE && status_running)
    {
        std::cout << "Now you have to choose if the algo must be ECDSA or RSA\n";
        input = getInputFromConsoleString();
        if(!input.has_value())
        {
            printFinalMessage();
            this->status_running = false;
            return Status::FAILURE;
        }
        else
        {
            inputFromConsole = input.value();
        }

        std::transform(inputFromConsole.begin(), inputFromConsole.end(), inputFromConsole.begin(), [](unsigned char c){return std::tolower(c);});
        if(inputFromConsole == "#")
        {
            return Status::FAILURE;
        }
        else
        {
            bool fl = false;
            if(inputFromConsole == "ecdsa")
            {
                fl = true;
                this->m_signClassType = Sign::ECDSA;
            }
            else if(inputFromConsole == "rsa")
            {
                fl = true;
                this->m_signClassType = Sign::RSA;
            }

            if(!fl)
            {
                std::cout << "The algo you entered is not support by program, try another\n";
            }
            else
            {
                return Status::SUCCESS;
            }
        }
    }
    return Status::FAILURE;
}

Status CertificateManager::chooseIfEncrypted()
{
    Status status = Status::FAILURE;
    std::optional<std::string> input;
    std::string inputFromConsole;
    while(status == Status::FAILURE && status_running)
    {
        std::cout << "Choose if cert must be encrypted: YES/No\n";
        input = getInputFromConsoleString();
        if(!input.has_value())
        {
            printFinalMessage();
            this->status_running = false;
            return Status::FAILURE;
        }
        else
        {
            inputFromConsole = input.value();
        }

        std::transform(inputFromConsole.begin(), inputFromConsole.end(), inputFromConsole.begin(), [](unsigned char c){return std::tolower(c);});
        if(inputFromConsole == "#")
        {
            return Status::FAILURE;
        }
        else if(inputFromConsole == "_")
        {
            printFinalMessage();
            status_running = false;
            return Status::FAILURE;
        }
        else
        {
            bool flag = false;
            // means have to parse yes or no
            if(inputFromConsole == "yes")
            {
                flag = true;
                this->m_passwdRequired = Passwd::YES;
            }
            else if(inputFromConsole == "no")
            {
                flag = true;
                this->m_passwdRequired = Passwd::NO;
            }
            if(!flag)
            {
                continue;
            }
            else 
            {
                std::cout << "ENC ok\n";
                if(signalFlag)
                {
                    status_running = false;
                    printFinalMessage();
                }
                return Status::SUCCESS;
            }
        }
    }
    return Status::FAILURE;
}

Status CertificateManager::CreateCert()
{
    // creatng a cerificate to the responding needs
    bool fl = true;
    std::optional<std::string> input;
    std::string val;
    do
    {
        std::cout << "Enter the name of certificate\n";
        input = getInputFromConsoleString();
        if(!input.has_value())
        {
            printFinalMessage();
            this->status_running = false;
            return Status::FAILURE;
        }
        else
        {
            val = input.value();
        }

        // have to verify if the name exist and available
        std::string tempPRIname;
        std::string tempPUBname;
        if(m_passwdRequired == Passwd::NO)
        {
            tempPRIname = this->m_pathToPriKey + "/" + val + "_pri.pem";
            tempPUBname = this->m_pathToPubKey + "/" + val + "_pub.pem";
        }    
        else
        {
            tempPRIname = this->m_pathToPriKey + "/" + val + "_pri.enc.pem";
            tempPUBname = this->m_pathToPubKey + "/" + val + "_pub.enc.pem";
        }
        // test 
        std::filesystem::path pathPRI = std::filesystem::absolute(tempPRIname);
        std::filesystem::path pathPUB = std::filesystem::absolute(tempPUBname);
        
        this->m_pathToPriKey = tempPRIname;
        this->m_pathToPubKey = tempPUBname;
        if(std::filesystem::exists(pathPRI) || std::filesystem::exists(pathPUB))
        {
            std::cout << "The files exists, enter other name\n";
        }
        else
        {
            std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> status;
            if(this->m_signClassType == Sign::RSA)
            {
                status = createRSACert();
                if(status.first != Status::SUCCESS)
                {
                    std::cout << "Cannot create the private key\n";
                    return Status::FAILURE;
                }
            }
            else if(this->m_signClassType == Sign::ECDSA)
            {
                status = createECDSACert();
                if(status.first != Status::SUCCESS)
                {
                    std::cout << "Cannot create the private key\n";
                    return Status::FAILURE;
                }
            }     
            std::fstream filePRI(pathPRI, std::ios::out);
            std::fstream filePUB(pathPUB, std::ios::out);
            status = WriteCertToFiles(filePRI, filePUB, std::move(status.second), this->m_signClassType);
            // means we have to delete the file we created
            if(status.first == Status::FAILURE)
            {
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
            return status.first;
        }
    }while(fl);
    return Status::FAILURE;
}

std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> CertificateManager::WriteCertToFiles(std::fstream &filePRI, std::fstream &filePUB, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY *)>> &&keyPair, Sign certType)
{
    // Private Key Encoding
    std::unique_ptr<char[]> propq(nullptr);                                                                                                                            
    std::unique_ptr<OSSL_ENCODER_CTX, std::function<void(OSSL_ENCODER_CTX*)>> E_ctx(OSSL_ENCODER_CTX_new_for_pkey(keyPair.get(), OSSL_KEYMGMT_SELECT_PRIVATE_KEY, "PEM", (certType == Sign::RSA)?"PKCS1":nullptr, propq.get()), this->customDeleter_OSSL_ENCODER_CTX);

    if(E_ctx.get() == nullptr)
    {
        std::cout << "Error with creating E_ctx\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }

    std::optional<std::string> inputPassword;
    std::string password;
    if(this->m_passwdRequired == Passwd::YES)
    {
        // Ask for a password to encrypt the private key
        std::cout << "Enter the password to encrypt the private key: ";
        inputPassword = getInputFromConsoleString();

        if(!inputPassword.has_value())
        {
            printFinalMessage();
            return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
        }
        else
        {
            password = inputPassword.value();
        }

        //test
        if(OSSL_ENCODER_CTX_set_cipher(E_ctx.get(), "AES-256-CBC", propq.get()) == 0)
        {
            std::cout << "Error with seting cipher\n";
            return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
        }
        // Set the passphrase to encrypt the private key
        OSSL_ENCODER_CTX_set_passphrase(E_ctx.get(), reinterpret_cast<const unsigned char*>(password.c_str()), password.size());
    }

    unsigned char *privateKeyData = nullptr;
    size_t privateKeyLen = 0;

    // Encode the private key into a data buffer
    if (OSSL_ENCODER_to_data(E_ctx.get(), &privateKeyData, &privateKeyLen) != 1)
    {
        std::cout << "Error with encoding private key to data\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
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
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }
    unsigned char *publicKeyData = nullptr; 
    size_t publicKeyLen = 0;
    // Encode the public key into a data buffer
    if (OSSL_ENCODER_to_data(E_ctx.get(), &publicKeyData, &publicKeyLen) != 1)
    {
        std::cout << "Error with encoding public key to data\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }
    // Writing public key data to file
    filePUB.write(reinterpret_cast<const char*>(publicKeyData), publicKeyLen);
    filePUB.close();
    // Free allocated memory
    OPENSSL_free(publicKeyData);
    std::cout << "Successfuly write a cert to files\n";
    return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::SUCCESS, nullptr);
}

Status CertificateManager::manualAddPrivateKey()
{
    Status tempStatus = Status::FAILURE;
    std::optional<std::string> inputConsole;
    std::string input;
    std::cout << "Enter the path to the certificate:\n";
    inputConsole = getInputFromConsoleString();
    if(!inputConsole.has_value())
    {
        this->status_running = false;
        printFinalMessage();
        return Status::FAILURE;
    }
    else
    {
        input = inputConsole.value();
    }

    tempStatus = verifyIfFile(input);
    if(tempStatus == Status::FAILURE)
    {
        std::cout << "The path you provided is not a valid path\n";
        status_running = false;
        return Status::FAILURE;
    }
    tempStatus = verifyValidPrivateKey(input);
    return tempStatus;
}

static int passwordCallback(char* buf, int size, int rwflag, void* userdata) {
    std::string password;
    std::cout << "Enter the password:\n";
    std::optional<std::string> passwOpt;

    passwOpt = getInputFromConsoleString();
    if(!passwOpt.has_value())
    {
        reinterpret_cast<CertificateManager*>(userdata)->status_running = false;
        buf = nullptr;
        return 0;
    }
    else
    {
        password = passwOpt.value();
    }
    size_t len = password.size();
#ifndef _MSC_VER 
    memcpy(buf, password.data(), password.size());
#else
    memcpy_s(buf, password.size(), password.data(), password.size());
#endif
    return len;
}

Status CertificateManager::verifyValidPrivateKey(const std::string &path)
{
    std::filesystem::path path_ = std::filesystem::absolute(path);
    std::unique_ptr<BIO, std::function<void(BIO*)>> bio(BIO_new_file(path_.string().c_str(),"r"), this->customDeleter_BIO);
    
    std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> key(nullptr, this->customDeleter_EVP_PKEY);
    EVP_PKEY* k = key.get();

    k = PEM_read_bio_PrivateKey(bio.get(), nullptr, passwordCallback, this);
    if(k == nullptr)
    {
        std::cout << "Error with password, or file is corrupted\n";
        return Status::FAILURE;
    }
    else
    {
        std::cout << "Got the private key!!!\n";
        key.reset(k);
        this->flagInitPrivate = true;
        this->m_pathToPriKey = path;
        return Status::SUCCESS;
    }
}

std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> CertificateManager::createRSACert()
{
    // the last nullptr for engine
    std::unique_ptr<EVP_PKEY_CTX, std::function<void(EVP_PKEY_CTX*)>> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), this->customDeleter_EVP_PKEY_CTX);
    if(ctx.get() == nullptr)
    {
        std::cout << "Error with EVP_PKEY_CTX_new_id\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }
    if(EVP_PKEY_keygen_init(ctx.get()) <= 0)
    {
        std::cout << "Error with initializing a keygen context\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }
    if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 4096) <= 0)
    {
        std::cout << "Cannot set the keygen bits in rsa\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }
    std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> keyPair(nullptr, this->customDeleter_EVP_PKEY);
    EVP_PKEY* k = keyPair.get();
    if(EVP_PKEY_keygen(ctx.get(), &k) <= 0)
    {
        std::cout << "Error with generating key pair\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }
    keyPair.reset(k);
    
    return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::SUCCESS, std::move(keyPair));
    //WriteCertToFiles(filePRI, filePUB, std::move(keyPair), Sign::RSA);
}

std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> CertificateManager::createECDSACert()
{
    // ec stands for eliptic curve
    std::unique_ptr<EVP_PKEY_CTX, std::function<void(EVP_PKEY_CTX*)>> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), this->customDeleter_EVP_PKEY_CTX);
    if(ctx.get() == nullptr)
    {
        std::cout << "Unable to create a EVP_PKEY_CTX for ecdsa\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }
    if(EVP_PKEY_keygen_init(ctx.get()) <= 0)
    {
        std::cout << "Unable to init a ctx for generating a key\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }
    if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime239v3) <= 0)
    {
        std::cout << "Cannot set this type of curve\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }
    std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> keyPair(nullptr, this->customDeleter_EVP_PKEY);
    EVP_PKEY* k = keyPair.get();
    if(EVP_PKEY_generate(ctx.get(), &k) <= 0)
    {
        std::cout << "Error with generating a key\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
    }
    keyPair.reset(k);
    // now we have a key-pair in the EVP_PKEY
    return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::SUCCESS, std::move(keyPair)); 
    //WriteCertToFiles(filePRI, filePUB, std::move(keyPair), Sign::ECDSA);
}

std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>> CertificateManager::extractPrivateKey()
{
    std::unique_ptr<BIO, std::function<void(BIO*)>> bio(BIO_new_file(std::filesystem::absolute(this->m_pathToPriKey).string().c_str(), "r") , this->customDeleter_BIO);
    if(bio.get() == nullptr)
    {
        std::cout << "Cannot create a bio from a file\n";
        return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
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
    std::optional<std::string> passwordOpt; 
    std::string password;
    while(needPassword)
    {
        std::cout << "Need a password:\n";
        passwordOpt = getInputFromConsoleString();
        if(!passwordOpt.has_value())
        {
            printFinalMessage();
            this->status_running = false;
            return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::FAILURE, nullptr);
        }
        else
        {
            password = passwordOpt.value();
            //  means we read password. If password is right, we can extract a key
            k = PEM_read_bio_PrivateKey(bio.get(), nullptr, passwordCallback, reinterpret_cast<void*>(this));
            if(k != nullptr)
            {
                std::cout << "Extracted the key successfully\n";
                needPassword = false;
            }
            else
            {
                std::cout << "Wrong password\n";
            }
        }
    }
    key.reset(k);
    return std::make_pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>>>(Status::SUCCESS, std::move(key));
}


std::pair<Status, std::vector<unsigned char>> CertificateManager::digitalSignDocument(const std::string &filename)
{
    std::filesystem::path path_ = std::filesystem::absolute(filename);
    const EVP_MD* hashAlgo = nullptr;
    if(this->m_algorithm == Hash::SHA_256)
    {
        hashAlgo = EVP_sha256();
    }
    else if(this->m_algorithm == Hash::SHA_512)
    {
        hashAlgo = EVP_sha512();
    }  
    
    auto status = extractPrivateKey();
    if(status.first == Status::FAILURE)
    {
        printFinalMessage();
        this->status_running = false;
        return std::make_pair<Status, std::vector<unsigned char>>(Status::FAILURE,std::vector<unsigned char>(0));
    }

    //so, we get the keys inside a PKEY unique_ptr
    std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> ctx(EVP_MD_CTX_new(), this->customDeleter_EVP_MD_CTX);
    if(ctx.get() == nullptr)
    {
        std::cout << "Cannot init a md ctx for hashing\n";
        return std::make_pair<Status, std::vector<unsigned char>>(Status::FAILURE,std::vector<unsigned char>(0));
    }
    if(EVP_DigestSignInit(ctx.get(), nullptr, hashAlgo, nullptr, status.second.get()) <= 0)
    {
        std::cout << "Error init and ctx for hashing with key\n";
        return std::make_pair<Status, std::vector<unsigned char>>(Status::FAILURE,std::vector<unsigned char>(0));
    }
    std::ifstream file(path_, std::ios::binary);
    if(!file)
    {
        std::cout << "Cannot open the file\n";
        return std::make_pair<Status, std::vector<unsigned char>>(Status::FAILURE,std::vector<unsigned char>(0));
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
        return std::make_pair<Status, std::vector<unsigned char>>(Status::FAILURE,std::vector<unsigned char>(0));
    }
    std::vector<unsigned char> signature(signatureLen);
    if (EVP_DigestSignFinal(ctx.get(), signature.data(), &signatureLen) <= 0) {
        std::cout << "Failed to generate the signature";
        return std::make_pair<Status, std::vector<unsigned char>>(Status::FAILURE,std::vector<unsigned char>(0));
    }
    // writing a digital signature into the file
    writeSignatureIntoFile(path_.string(), signature);
    return std::make_pair<Status, std::vector<unsigned char>>(Status::SUCCESS, std::move(signature));
}

void CertificateManager::writeSignatureIntoFile(const std::string &path, std::vector<unsigned char> &signature)
{
    std::filesystem::path path_ = std::filesystem::absolute(path);
    std::filesystem::path pathForCreation = path_.parent_path();
    std::string fileName = std::string(path_.filename().string()) + ((this->m_signClassType == Sign::RSA) ? "_rsa.bin" : "_ecdsa.bin");
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

void CertificateManager::configureCertificatePublicKey()
{
    Status status = Status::FAILURE;
    std::optional<std::string> inputFromConsoleOpt;
    std::string inputFromConsole;
    do
    {   
        std::cout << "\n================\n"
                  << "This program only supports verifying using an existing publiic key.\n" 
                  << "So you must specify the public key path:\n";
        inputFromConsoleOpt = getInputFromConsoleString();
        if(!inputFromConsoleOpt.has_value())
        {
            status_running = false;
            printFinalMessage();
            return ;
        }
        else
        {
            inputFromConsole = inputFromConsoleOpt.value();
        }

        std::transform(inputFromConsole.begin(), inputFromConsole.end(), inputFromConsole.begin(), [](unsigned char c){return std::tolower(c);});   
        if(inputFromConsole == "#")
        {
            continue;
        }
        else
        {
            // get the path to the public key
            status = verifyIfFile(inputFromConsole);
            if(status == Status::FAILURE)
            {
                std::cout << "Wrong file specified\n";
                continue;
            }
            // check if the public key is valid
            status = verifyValidPublicKey(inputFromConsole);
            if(status == Status::FAILURE)
            {
                std::cout << "The public key is corrupted\n";
            }
            else
            {
                std::cout << "Added the valid public key\n";
            }      
        }
    } while (status == Status::FAILURE && status_running);
}

Status CertificateManager::verifyValidPublicKey(const std::string &path)
{
    std::filesystem::path path_ = std::filesystem::absolute(path);
    std::unique_ptr<BIO, std::function<void(BIO*)>> bio(BIO_new_file(path_.string().c_str(),"r"), this->customDeleter_BIO);
    if(bio.get() == nullptr)
    {
        std::cout << "Error with loading a public key\n";
        return Status::FAILURE;
    }
    std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> key(nullptr, this->customDeleter_EVP_PKEY);
    EVP_PKEY* k = key.get();
    // test
    k = PEM_read_bio_PUBKEY(bio.get(), nullptr, passwordCallback, this);
    if(k == nullptr)
    {
        std::cout << "Cannot read the public key from bio\n";
        return Status::FAILURE;
    }
    else
    {
        std::cout << "The public key is valid!!!\n";
        this->flagInitPublic = true;
        this->m_pathToPubKey = path;
        return Status::SUCCESS;
    }
}

bool CertificateManager::verifyDigitalSign(const std::string &pathToFile, const std::string &pathToSignature)
{
    std::filesystem::path pathFiles = std::filesystem::absolute(pathToFile);
    std::ifstream fileMain(pathFiles, std::ios::binary);
    if(!fileMain)
    {
        std::cout << "Cannot open the file\n";
        return false;
    }
    std::filesystem::path pathSignature = std::filesystem::absolute(pathToSignature);
    std::ifstream fileSignature(pathSignature, std::ios::binary);
    if(!fileSignature)
    {
        std::cout << "Cannot open the file\n";
        return false;
    }
    std::string signature((std::istreambuf_iterator<char>(fileSignature)), std::istreambuf_iterator<char>());

    std::filesystem::path keyPath = std::filesystem::absolute(this->m_pathToPubKey);
    std::unique_ptr<BIO, std::function<void(BIO*)>> bio(BIO_new_file(keyPath.string().c_str(),"r"), this->customDeleter_BIO);
    if(bio.get() == nullptr)
    {
        std::cout << "Error with a bio\n";
    }
    std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY*)>> key (nullptr, this->customDeleter_EVP_PKEY);
    EVP_PKEY* k = key.get();
    
    k = PEM_read_bio_PUBKEY(bio.get(), nullptr, passwordCallback, this);
    if(k == nullptr)
    {
        std::cout << "Error with a public key\n";
        return false;
    }
    std::cout << "Public key is successfully extracted\n";
    key.reset(k);

    // prompt for the sha algo
    std::optional<std::string> input;
    std::string algo;
    Hash localAlgo;
    do
    {
        std::cout << "Enter the SHA-256 or SHA-512 algorithm for verification\n";
        std::cin >> algo;
        input = getInputFromConsoleString();
        if(!input.has_value())
        {
            printFinalMessage();
            this->status_running = false;
            return false;
        }
        else
        {
            algo = input.value();
        }

        std::transform(algo.begin(), algo.end(), algo.begin(), [](char c){return std::tolower(c);});
        if(algo == "sha-512")
        {
            localAlgo = Hash::SHA_512;
            break;
        }
        else if(algo == "sha-256")
        {
            localAlgo = Hash::SHA_256;
            break;
        }
        else
        {
            std::cout << "Wrong algo!!\n";
        }
    }
    while(true);
    
    // now we have an algo

    std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> ctx(EVP_MD_CTX_new(), this->customDeleter_EVP_MD_CTX);
    if(ctx.get() == nullptr)
    {
        std::cout << "Cannot create new md ctx \n";
        return false;
    }

    const EVP_MD* algoEVP;
    if(localAlgo == Hash::SHA_256)
    {
        algoEVP = EVP_sha256();
    }
    else
    {
        algoEVP = EVP_sha512();
    }

    if(EVP_DigestVerifyInit(ctx.get(), nullptr, algoEVP, nullptr, key.get()) <= 0)
    {
        std::cout << "Cannot initialize a verify context\n";
        return false;
    }

    const size_t bufferSize = 1024 * 1024; // 1 MB buffer
    std::vector<unsigned char> buffer(bufferSize);

    while (fileMain.read(reinterpret_cast<char*>(buffer.data()), bufferSize)) {
        if (EVP_DigestVerifyUpdate(ctx.get(), reinterpret_cast<unsigned char*>(buffer.data()), fileMain.gcount()) <= 0) {
            std::cerr << "Failed to update verification with file data" << std::endl;
            return false;
        }
    }
    if (fileMain.gcount() > 0) {
        if (EVP_DigestVerifyUpdate(ctx.get(), reinterpret_cast<char*>(buffer.data()), fileMain.gcount()) <= 0) {
            std::cerr << "Failed to update verification with file data" << std::endl;
            return false;
        }
    }

    bool result = EVP_DigestVerifyFinal(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size()) == 1;

    if (result) {
        std::cout << "Signature verification successful!" << std::endl;
    } else {
        std::cerr << "Signature verification failed!" << std::endl;
    }
    return result;
}

std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY *)>>> CertificateManager::public_createRSACert(Passwd passwd, Hash hash, Sign sign)
{
    this->m_passwdRequired = passwd;
    this->m_algorithm = hash;
    this->m_signClassType = sign;
    return this->createRSACert();
}

std::pair<Status, std::unique_ptr<EVP_PKEY, std::function<void(EVP_PKEY *)>>> CertificateManager::public_createECDSACert(Passwd passwd, Hash hash, Sign sign)
{
    this->m_passwdRequired = passwd;
    this->m_algorithm = hash;
    this->m_signClassType = sign;
    return this->createECDSACert();
}
