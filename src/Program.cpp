#include "Program.h"
#include "Service.h"

#include <string>
#include <algorithm>

Program::Program()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    m_service = std::make_unique<Service>();
}

Program::~Program()
{
    std::cout << "Destructor called\n";
    EVP_cleanup();
}


std::string Program::getInputFromConsoleNum()
{
    std::string input = "0";
    if(!std::cin.eof() && this->m_status)
    {
        std::cin >> input;
    }
    return input;
}

std::string Program::getInputFromConsoleString()
{
    std::string input;
    std::cin >> input;
    if(std::cin.eof())
        input = "_";
    return input;
}

void Program::printFinalMessage()
{
    std::cout << "\nThank you, have a nice day\n";
}

void Program::start()
{
    std::string input;
    int dec = 1;
    while(m_status)
    {
        std::cout << "Enter the command from the list to start working with program:\n";
        std::cout << "\t1 - sign a document using ecdsa or rsa\n";
        std::cout << "\t2 - verify a signature\n";
        std::cout << "\t3 - get the hash of document\n";
        std::cout << "\t4 - set the parameters\n";
        std::cout << "\t0 - exit the program\n";
        input = getInputFromConsoleNum();
        try
        {
            dec = std::stoi(input);
            if(std::cin.eof())
                dec = 0;
        }
        catch(...)
        {
            std::cout << "Error in entered num, try again\n";
            std::cin.clear();
            continue; 
        }
        switch (dec)
        {
        case 1:
            
            break;
        case 2:
            
            break;
        case 3:
            std::cout << "The algo for hashing(to change it, select 4 in start menu): " << m_service->getHashType(); 
            std::cout << "Enter the path to the file: " ;
            break;
        case 4:
            
            break;
        case 0:
            printFinalMessage();
            m_status = false;
            continue;
            break;
        default:
            std::cout << "Wrong option, choose another\n";
            continue;
            break;
        }

    }
}

void Program::setStatus(bool status)
{
    this->m_status = status;
}

Status Program::configureHash()
{
    Status status = Status::FAILURE;
    std::string input;
    do
    {
        std::cout << "Enter hash algo: SHA-256 or SHA-512:\n";
        input = getInputFromConsoleString();
        std::transform(input.begin(), input.end(), input.begin(), [](unsigned char c){return std::tolower(c);});
        if(input != "_")
        {
            status = m_service->setHashType(input);
            if(status== Status::FAILURE)
                std::cout << "Wrong name of hash algo\n";
        }
        else
        {
            printFinalMessage();
            m_status = false;
            break;
        }
    }
    while(status == Status::FAILURE && m_status);
    return status;
}

Status Program::chooseIfEncrypted()
{
    Status status = Status::FAILURE;
    std::string inputFromConsole;
    while(status == Status::FAILURE && m_status)
    {
        std::cout << "Choose if cert must be encrypted: YES/No\n";
        inputFromConsole = getInputFromConsoleString();
        std::transform(inputFromConsole.begin(), inputFromConsole.end(), inputFromConsole.begin(), [](unsigned char c){return std::tolower(c);});
        if(inputFromConsole == "#")
        {
            return Status::FAILURE;
        }
        else if(inputFromConsole == "_")
        {
            printFinalMessage();
            m_status = false;
            return Status::FAILURE;
        }
        else
        {
            bool flag = false;
            // means have to parse yes or no
            if(inputFromConsole == "yes")
            {
                flag = true;
                m_service->setPasswd(Passwd::YES);
            }
            else if(inputFromConsole == "no")
            {
                flag = true;
                m_service->setPasswd(Passwd::NO);
            }
            if(!flag)
            {
                continue;
            }
            else 
            {
                std::cout << "ENC ok\n";
                status = m_service->CreateCert();
                if(m_service->signalFlag)
                {
                    this->m_status = false;
                    printFinalMessage();
                }
                return status;
            }
        }
    }
    return Status::FAILURE;
}

Status Program::chooseAlgoSigning()
{
    Status status = Status::FAILURE;
    std::string inputFromConsole;
    while(status == Status::FAILURE && m_status)
    {
        std::cout << "Now you have to choose if the algo must be ECDSA or RSA\n";
        inputFromConsole = getInputFromConsoleString();
        std::transform(inputFromConsole.begin(), inputFromConsole.end(), inputFromConsole.begin(), [](unsigned char c){return std::tolower(c);});
        if(inputFromConsole == "#")
        {
            return Status::FAILURE;
        }
        else if(inputFromConsole == "_")
        {
            printFinalMessage();
            m_status = false;
            return Status::FAILURE;
        }
        else
        {
            bool fl = false;
            if(inputFromConsole == "ecdsa")
            {
                fl = true;
                m_service->setSign(Sign::ECDSA);
            }
            else if(inputFromConsole == "rsa")
            {
                fl = true;
                m_service->setSign(Sign::RSA);
            }

            if(!fl)
            {
                std::cout << "The algo you entered is not support by program, try another\n";
            }
            else
            {
                // means the algo is good 
                // now have to prompt if the algo must be encrypted
                status = chooseIfEncrypted();
                if(status == Status::FAILURE)
                {
                    // means we only want to change the algo
                    continue;
                }
                else
                {
                    return Status::SUCCESS;
                }
            }

        }
    }
    return Status::FAILURE;
}

Status Program::createNewCert()
{
    Status status = Status::FAILURE;
    // now we have to read a path
    std::string input;
    while(status == Status::FAILURE && m_status)
    {
        std::cout << "Enter the path to place where cert will be stored\n";
        input = getInputFromConsoleString();
        if(input == "#")
        {
            return Status::FAILURE;
        }
        if(input == "_")
        {
            printFinalMessage();
            m_status = false;
            return Status::FAILURE;
        }
        else
        {
            // here we verify the path
            status = m_service->verifyIfFolder(input);
            if(status == Status::FAILURE)
            {
                // means not foolder
                std::cout << "The entered path is not a folder\n";
            }
            else 
            {
                std::cout << "Path OK\n";
                m_service->setPathToNewCertFolder(input);
                // now we have to ask which algo user wants
                status = chooseAlgoSigning();
                if(status == Status::FAILURE)
                {
                    // measn we want to change the path to the cert
                    continue;
                }
                else
                {
                    return Status::SUCCESS;
                }
            }
        }
    }
    return Status::FAILURE;
}


Status Program::configureCert()
{
    Status status = Status::FAILURE;
    std::string inputFromConsole;
    do
    {   
        std::cout << "This program only supports signing using ECDSA or RSA.\n" 
                  << "So you must choose:\n"
                  << "\tNEW to create a new pri and public key in pecified path\n"
                  << "\tMANUAL to manual write the path to private and public key\n";
        inputFromConsole = getInputFromConsoleString();
        std::transform(inputFromConsole.begin(), inputFromConsole.end(), inputFromConsole.begin(), [](unsigned char c){return std::tolower(c);});
        if(inputFromConsole == "new")
        {
            // now call the function
            m_service->setState(CertState::NEW);
            status = createNewCert();
            if(status == Status::FAILURE && m_status)
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

        }
        else if(inputFromConsole == "#")
        {
            continue;
        }
        else if(inputFromConsole == "_")
        {
            m_status = false;
            printFinalMessage();
            return Status::FAILURE;
        }
        else
        {
            std::cout << "Wrong option.....\n"; 
        }

    } while (status == Status::FAILURE && m_status);
    return status;
}

void Program::configureLib()
{
    std::cout << "Now you must set which hash func you want to use, and certificate for verification(soon you can change it)\n";
    Status status = configureHash();
    if(!m_status || status == Status::FAILURE)
        return;
    status = configureCert();
    if(!m_status || status == Status::FAILURE)
        return;
}

void Program::configureHashPublic()
{
    Status status = configureHash();
    if(!m_status || status == Status::FAILURE)
        return;
}

void Program::configureCertPublic()
{
    Status status = configureCert();
    if(!m_status || status == Status::FAILURE)
        return;
}
