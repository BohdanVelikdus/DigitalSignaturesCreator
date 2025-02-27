#include "gtest/gtest.h"

#include "HashManager.h"
#include "CertificateManager.h"
#include "Program.h"
#include "Service.h"
#include "DigitalSignaturesCreator.h"

#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <memory>
#include <optional>

bool status_running = true;

std::string vectorToHexString(const std::vector<unsigned char>& hash) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (unsigned char byte : hash) {
        oss << std::setw(2) << static_cast<int>(byte);
    }

    return oss.str();
}

std::string get_ec_curve_name(EVP_PKEY* pkey) {
    if (!pkey) {
        std::cerr << "EVP_PKEY is null." << std::endl;
        return "";
    }

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        std::cerr << "Key is not an EC key." << std::endl;
        return "";
    }

    size_t len = 0;
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0, &len) != 1) {
        std::cerr << "Failed to get curve name length." << std::endl;
        return "";
    }

    std::string curve_name(len, '\0');
    if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, curve_name.data(), len, &len) != 1) {
        std::cerr << "Failed to extract curve name." << std::endl;
        return "";
    }

    return curve_name;
}

TEST(Hashing, SHA_512_file)
{
    std::unique_ptr<HashManager> hashManager = std::make_unique<HashManager>(status_running);
    hashManager->setHashType("sha-512");
    std::string tests_path = std::string(TEST_PATH);
    tests_path += "/rsa/def/text";
    std::optional<std::vector<unsigned char>> res = hashManager->getHashOfDocumentByPath(tests_path);
    std::string output = vectorToHexString(res.value());
    std::string expected_Output = "8af9a0322f5ba4dc644600a28ab9536a8e7bb74392abed0543ccff564fce0fdb57dc081180b6c2833b5da76607e3217bb87b2e46536cb71a475c5ca312ebcd20";
    if(res.has_value())
    {
        ASSERT_EQ(output, expected_Output);
    }
    else 
    {
        ASSERT_EQ(1,2);
    }
    res = hashManager->getHashOfDocumentByPath(tests_path);
    output = vectorToHexString(res.value());
    if(res.has_value())
    {
        ASSERT_EQ(output, expected_Output);
    }
    else 
    {
        ASSERT_EQ(1,2);
    }
}

TEST(Hashing, SHA_256_file)
{
    std::unique_ptr<HashManager> hashManager = std::make_unique<HashManager>(status_running);
    hashManager->setHashType("sha-256");
    std::string tests_path = std::string(TEST_PATH);
    tests_path += "/rsa/enc/text";
    std::optional<std::vector<unsigned char>> res = hashManager->getHashOfDocumentByPath(tests_path);
    std::string output = vectorToHexString(res.value());
    std::string expected_Output = "d58851b5ea8a3ab8ea6251fc89452cc9a9107938ca61b1369ab611fbafe189a0";
    if(res.has_value())
    {
        ASSERT_EQ(output, expected_Output);
    }
    else 
    {
        ASSERT_EQ(1,2);
    }
    res = hashManager->getHashOfDocumentByPath(tests_path);
    output = vectorToHexString(res.value());
    if(res.has_value())
    {
        ASSERT_EQ(output, expected_Output);
    }
    else 
    {
        ASSERT_EQ(1,2);
    }
}

TEST(RSA, gen_pair)
{
    std::unique_ptr<CertificateManager> certificateManager(new CertificateManager(status_running));
    auto pair = certificateManager->public_createRSACert(Passwd::NO, Hash::SHA_512, Sign::RSA);
    ASSERT_EQ(pair.first, Status::SUCCESS);
    std::unique_ptr<BIGNUM, std::function<void(BIGNUM*)>> bn(nullptr, ::BN_free);
    BIGNUM* b =  bn.get();
    int bits;
    if(EVP_PKEY_get_bn_param(pair.second.get(), "n", &b) == 1 && b)
    {
        bits = BN_num_bits(b);
    }
    bn.reset(b);
    ASSERT_EQ(bits, 4096);
}

TEST(ECDSA, gen_pair)
{
    std::unique_ptr<CertificateManager> certificateManager(new CertificateManager(status_running));
    auto pair = certificateManager->public_createECDSACert(Passwd::NO, Hash::SHA_512, Sign::RSA);
    ASSERT_EQ(pair.first, Status::SUCCESS);
}




