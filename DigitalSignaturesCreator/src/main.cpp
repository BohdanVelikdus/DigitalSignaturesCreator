#include <iostream>
#include <csignal>
#include <string>
#include <thread>
#include <chrono>

#include <signal.h>
#include <stdlib.h>


#include "openssl/evp.h"
#include "openssl/rsa.h"

using namespace std::literals;

#include "Program.h"
#include "DigitalSignaturesCreator.h"

std::shared_ptr<Program> pr;

void exitGracefully(int)
{
    pr->setStatus(false);
    std::cin.rdbuf()->pubsync(); 
    std::cin.setstate(std::ios::eofbit);
    fclose(stdin);
}


void func()
{
    std::signal(SIGINT, exitGracefully);
    std::cout << "DigitalSignaturesCreator. Vesrion: " << DigitalSignaturesCreator_VERSION_MAJOR << "." << DigitalSignaturesCreator_VERSION_MINOR << "\n";
    std::cout << "=====================\n";
    pr = std::make_shared<Program>();
    if (OpenSSL_add_all_algorithms() == 0) {
        std::cout << "Error: OpenSSL failed to load algorithms.\n";
    }
    //pr->configureLib();
    pr->configureHashPublic();
    pr->start();
}

int main() 
{
    try
    {
        func();
    }
    catch(...)
    {
        throw;
    }
    return 0;
}