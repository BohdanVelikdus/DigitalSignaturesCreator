#include "Program.h"
#include "Service.h"

#include <string>
#include <algorithm>
#include <functional>

extern bool status_running; 

Program::Program()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    m_hashManager = std::make_unique<HashManager>();
    m_certificateManager = std::make_unique<CertificateManager>();
    CertificateManager* forCallback = m_certificateManager.get();
    m_hashManager->setCallbackChangingHash(
        [forCallback](Hash newHash)
        {
            forCallback->setAlgorithmChange(newHash);
        });
}

Program::~Program()
{
    std::cout << "Destructor called\n";
    EVP_cleanup();
}

void Program::start()
{
    m_hashManager->configureHash();
    std::string input;
    int dec = 1;
    while(status_running)
    {
        std::cout << "Enter the command from the list to start working with program:\n";
        std::cout << "\t1 - sign a document using ecdsa or rsa\n";
        std::cout << "\t2 - verify a signature\n";
        std::cout << "\t3 - get the hash of document\n";
        std::cout << "\t4 - set the parameters\n";
        std::cout << "\t0 - exit the program\n";
        Status tempStatus = Status::FAILURE;
        std::string pathToFileForHash = "";
        std::string pathToFileForVeryfing = "";
        std::string pathToFileDigitalSignature = "";
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
            // sign a document using a certificate, mentioned in a file
            while(!m_certificateManager->getInitFlagPriKey())
            {
                std::cout << "Need a new private key\n";
                m_certificateManager->configureCertificatePrivateKey();
            }
            do
            {
                std::cout << "\nEnter the path to the file:\n";
                input = getInputFromConsoleString();
                if(input == "_")
                {
                    status_running = false;
                    return;
                }
                if(input == "#")
                {
                    break;
                }
                else
                {
                    tempStatus = verifyIfFile(input);
                    if(tempStatus == Status::FAILURE)
                    {
                        std::cout <<  "Wrong file\n";
                        continue;
                    }
                    tempStatus = m_certificateManager->digitalSignDocument(input);  
                }
            }while(tempStatus == Status::FAILURE);
            std::cout << "Successfully create a new digital signature\n";
            break;
        case 2:
            // verifying a signature 
            // verifying a signature using a public key, mentioned in a file
            while(!m_certificateManager->getInitFlagPubKey())
            {
                std::cout << "Need a new public key\n";
                m_certificateManager->configureCertificatePublicKey();
            }
            do
            {
                std::cout << "\nEnter the path to the file:\n";
                pathToFileForVeryfing = getInputFromConsoleString();
                if(pathToFileForVeryfing == "_")
                {
                    status_running = false;
                    return;
                }
                if(pathToFileForVeryfing == "#")
                {
                    break;
                }             
                tempStatus = verifyIfFile(pathToFileForVeryfing);
                if(tempStatus == Status::FAILURE)
                {
                    std::cout <<  "Wrong file\n";
                    continue;
                }
                std::cout << "\nEnter the path to the digital signature of file:\n";
                pathToFileDigitalSignature = getInputFromConsoleString();
                if(pathToFileDigitalSignature == "_")
                {
                    status_running = false;
                    return;
                }
                if(pathToFileDigitalSignature == "#")
                {
                    break;
                }             
                tempStatus = verifyIfFile(pathToFileDigitalSignature);
                if(tempStatus == Status::FAILURE)
                {
                    std::cout <<  "Wrong file\n";
                    continue;
                }
                m_certificateManager->verifyDigitalSign(pathToFileForVeryfing, pathToFileDigitalSignature);  
            }
            while(tempStatus == Status::FAILURE);
            break;
        case 3:
            std::cout << "The algo for hashing(to change it, select 4 in start menu)(# to return to the menu): " << m_hashManager->getHashType(); 
            do
            {
                std::cout << "\nEnter the path to the file:\n";
                input = getInputFromConsoleString();
                if(input == "_")
                {
                    status_running = false;
                    return;
                }
                if(input == "#")
                {
                    break;
                }
                else
                {
                    // we get the path to the file, so have to verify a path
                    tempStatus = verifyIfFile(input);
                    if(tempStatus ==  Status::SUCCESS)
                    {
                        pathToFileForHash = input;
                        // the file exists, so create a hash of it
                        std::optional<std::vector<unsigned char>> hash = m_hashManager->getHashOfDocumentByPath(input);
                        if(hash.has_value())
                        {
                            tempStatus = Status::SUCCESS;
                            std::cout << "Got the hash of file, printing...\n";
                            for (unsigned char byte : hash.value()) {
                                std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
                            }
                            std::cout << std::endl;
                            std::cout << "Do you want to write it into file(YES/NO):\n";
                            input = getInputFromConsoleString();
                            if(input == "_")
                            {
                                return;
                            }
                            else
                            {
                                std::transform(input.begin(), input.end(), input.begin(), [](auto c){return std::tolower(c);});
                                if(input == "yes")
                                {
                                    // have to save into a file
                                    m_hashManager->writeHashIntoFile(pathToFileForHash, hash.value());
                                }                                
                            }
                        }
                        else
                        {
                            std::cout << "Enter other path";
                        }
                    }
                    else
                    {
                        std::cout << "The file is not correct, enter other path for file\n";
                    }
                }
            }
            while(tempStatus == Status::FAILURE);
            break;
        case 4:
            // manual set of the private key and public key
            // have to separate a definitionn of all of them
            do
            {
                std::cout << "You want to configure (enter) a (PUBLIC) or PRIVATE:\n";
                input = getInputFromConsoleString();
                std::transform(input.begin(), input.end(), input.begin(), [](char c ){return std::tolower(c);});
                if(input == "public")
                {
                    m_certificateManager->configureCertificatePublicKey();
                    break;
                }
                else if(input == "private")
                {
                    m_certificateManager->configureCertificatePrivateKey();
                    break;
                }
                else if(input == "_")
                {
                    printFinalMessage();
                    status_running = false;
                    return;
                }
                else
                {
                    std::cout << "Enter other message\n";
                }
            }while(true);
            break;
        case 0:
            printFinalMessage();
            status_running = false;
            continue;
            break;
        default:
            std::cout << "Wrong option, choose another\n";
            continue;
            break;
        }

    }
}

#pragma endregion




