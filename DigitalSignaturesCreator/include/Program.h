#pragma once

#include <memory>
#include <filesystem>
#include <iostream>

#include <openssl/pem.h>
#include <openssl/err.h>

#include "Service.h"

class Program
{
public:
    Program();

    ~Program();

    void start();

    void setStatus(bool status);

    std::string getInputFromConsoleNum();

    std::string getInputFromConsoleString();
    
    void configurePrivateKey();

    Status createNewCertificatePublicAndPrivateKey();



    Status configureHash();

    Status configureCert();


    Status chooseAlgoSigning();

    Status chooseIfEncrypted();




    void configureHashPublic();

    void configureCertPublic();

    void printFinalMessage();

private:
    bool m_status = true;
    std::unique_ptr<Service> m_service;
};


