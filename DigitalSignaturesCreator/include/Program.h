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

    void start();

    void setStatus(bool status);

    std::string getInputFromConsoleNum();

    std::string getInputFromConsoleString();

    ~Program();
    
    Status configureHash();

    Status configureCert();

    Status createNewCert();

    Status chooseAlgoSigning();

    Status chooseIfEncrypted();

    void configureLib();

    void configureHashPublic();

    void configureCertPublic();

    void printFinalMessage();

private:
    bool m_status = true;
    std::unique_ptr<Service> m_service;
};


