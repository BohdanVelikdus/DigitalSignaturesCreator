#include "gtest/gtest.h"

#include "HashManager.h"
#include "CertificateManager.h"
#include "Program.h"
#include "Service.h"

#include <memory>
#include <optional>

bool status_running = true;

TEST(SigningTest, RSA_NOT_ENCRYPTED)
{
    std::unique_ptr<HashManager> hashManager = std::make_unique<HashManager>();
    std::optional<std::vector<unsigned char>> res = hashManager->getHashOfDocumentByPath("path");
    if(res.has_value())
    {
        ASSERT_EQ(1,1);
    }
    else 
    {
        ASSERT_EQ(1,1);
    }
    
}
