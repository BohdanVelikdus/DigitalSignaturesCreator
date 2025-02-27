#include "Program.h"
#include "Service.h"

#include <string>
#include <algorithm>
#include <functional>

Program::Program() : m_hashManager((new HashManager(this->status_running))),
    m_certificateManager(new CertificateManager(this->status_running))
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    CertificateManager* forCallback = m_certificateManager.value().get();
    m_hashManager.value()->setCallbackChangingHash(
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
    m_hashManager.value()->configureHash();
    std::optional<std::string> input;
    std::optional<int> dec;
    std::string in; 
    while(status_running)
    {
        std::cout << "Enter the command from the list to start working with program:\n";
        std::cout << "\t1 - sign a document using ecdsa or rsa\n";
        std::cout << "\t2 - verify a signature\n";
        std::cout << "\t3 - get the hash of document\n";
        std::cout << "\t4 - set the parameters\n";
        std::cout << "\t0 - exit the program\n";
        Status tempStatus = Status::FAILURE;
        std::pair<Status, std::vector<unsigned char>> digitalSignStatus;
        std::string pathToFileForHash = "";
        std::string pathToFileForVeryfing = "";
        std::string pathToFileDigitalSignature = "";
        std::string hashString = "";
        dec = getInputFromConsoleNum();
        if(!dec.has_value())
        {
            printFinalMessage();
            return;
        }
        switch (dec.value())
        {
        case 1:
            // sign a document using a certificate, mentioned in a file
            while(!m_certificateManager.value()->getInitFlagPriKey())
            {
                std::cout << "Need a new private key\n";
                m_certificateManager.value()->configureCertificatePrivateKey();
            }
            while(tempStatus == Status::FAILURE && this->status_running)
            {
                std::cout << "\nEnter the path to the file:\n";
                input = getInputFromConsoleString();
                if(!input.has_value())
                {
                    printFinalMessage();
                    status_running = false;
                    return;
                }
                else
                {
                    in = input.value();
                }

                if(in == "#")
                {
                    break;
                }
                else
                {
                    tempStatus = verifyIfFile(in);
                    if(tempStatus == Status::FAILURE)
                    {
                        std::cout <<  "Wrong file\n";
                        continue;
                    }
                    digitalSignStatus = m_certificateManager.value()->digitalSignDocument(in);  
                    if(digitalSignStatus.first == Status::SUCCESS)
                    {
                        std::cout << "Successfully create a new digital signature\n";
                    }
                    else 
                    {
                        std::cout << "The signature didn\'t created\n";
                    }
                }
            }
            break;
        case 2:
            // verifying a signature 
            // verifying a signature using a public key, mentioned in a file
            while(!m_certificateManager.value()->getInitFlagPubKey())
            {
                std::cout << "Need a new public key\n";
                m_certificateManager.value()->configureCertificatePublicKey();
            }
            do
            {
                std::cout << "\nEnter the path to the file:\n";
                input = getInputFromConsoleString();
                if(!input.has_value())
                {
                    printFinalMessage();
                    this->status_running = false;
                    return;
                }
                else
                {
                    pathToFileForVeryfing = input.value();
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
                input = getInputFromConsoleString();
                if(!input.has_value())
                {
                    printFinalMessage();
                    this->status_running = false;
                    return;
                }
                else
                {
                    pathToFileDigitalSignature = input.value();
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
                m_certificateManager.value()->verifyDigitalSign(pathToFileForVeryfing, pathToFileDigitalSignature);  
            }
            while(tempStatus == Status::FAILURE);
            break;
        case 3:
            std::cout << "The algo for hashing(to change it, select 4 in start menu)(# to return to the menu): " << m_hashManager.value()->getHashType(); 
            do
            {
                std::cout << "\nEnter the path to the file:\n";
                input = getInputFromConsoleString();
                if(!input.has_value())
                {
                    printFinalMessage();
                    this->status_running = false;
                    return;
                }   
                else
                {
                    pathToFileForHash = input.value();
                }

                if(input == "#")
                {
                    break;
                }
                else
                {
                    // we get the path to the file, so have to verify a path
                    tempStatus = verifyIfFile(pathToFileForHash);
                    if(tempStatus ==  Status::SUCCESS)
                    {
                        // the file exists, so create a hash of it
                        std::optional<std::vector<unsigned char>> hash = m_hashManager.value()->getHashOfDocumentByPath(pathToFileForHash);
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
                            if(!input.has_value())
                            {
                                printFinalMessage();
                                this->status_running = false;
                                return;
                            }
                            else
                            {
                                hashString = input.value();
                            }
                            std::transform(hashString.begin(), hashString.end(), hashString.begin(), [](unsigned char c){return std::tolower(c);});
                            if(hashString == "yes")
                            {
                                // writing to a file
                                m_hashManager.value()->writeHashIntoFile(pathToFileForHash, hash.value());
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
                if(!input.has_value())
                {
                    printFinalMessage();
                    this->status_running = false;
                    return;
                }
                else
                {
                    hashString = input.value();
                }
                std::transform(hashString.begin(), hashString.end(), hashString.begin(), [](char c ){return std::tolower(c);});
                if(input == "public")
                {
                    m_certificateManager.value()->configureCertificatePublicKey();
                    break;
                }
                else if(input == "private")
                {
                    m_certificateManager.value()->configureCertificatePrivateKey();
                    break;
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




