#pragma once

#include <memory>
#include <filesystem>
#include <iostream>

#include <openssl/pem.h>
#include <openssl/err.h>

#include "Service.h"
#include "HashManager.h"
#include "CertificateManager.h"

class Program
{
public:
    Program();

    ~Program();

    Status configureHash();

    void start();

    bool status_running = true;

private:
    std::optional<std::unique_ptr<HashManager>> m_hashManager;
    std::optional<std::unique_ptr<CertificateManager>> m_certificateManager;
};

