#include <iostream>
#include <csignal>
#include <string>
#include <thread>
#include <chrono>
#include <assert.h>

#include <signal.h>
#include <stdlib.h>

using namespace std::literals;

#include "Program.h"
#include "DigitalSignaturesCreator.h"


#define RESET   "\033[0m"
#define CYAN    "\033[36m"
#define YELLOW  "\033[33m"



std::shared_ptr<Program> pr;

void exitGracefully(int)
{
    pr->status_running = false;
    std::cin.rdbuf()->pubsync(); 
    std::cin.setstate(std::ios::eofbit);
    fclose(stdin);
}


int main() 
{
    std::signal(SIGINT, exitGracefully);
    std::cout << CYAN << R"(
        ____  _       _ _       _     _       
       |  _ \(_) __ _(_) |_ ___| |__ (_)_ __  
       | | | | |/ _` | | __/ _ \ '_ \| | '_ \
       | |_| | | (_| | | ||  __/ | | | | | | |
       |____/|_|\__, |_|\__\___|_| |_|_|_| |_|
                |___/                          
          )" << YELLOW << "\n        --- Digital Signer ---\n" << RESET;
    std::cout << "DigitalSignaturesCreator. Vesrion: " << DigitalSignaturesCreator_VERSION_MAJOR << "." << DigitalSignaturesCreator_VERSION_MINOR << "\n";
    std::cout << "=====================\n";
    pr = std::make_shared<Program>();
    pr->start();
    return 0;
}