#include "catch.hpp"
#define NO_MAIN
#include "../AES/aes-modes.cpp"

TEST_CASE("Encryption", "[Encryption]"){

    byte key[AES::DEFAULT_KEYLENGTH];
    const unsigned char a[] = "1234567890123456";
    copy(a, a + sizeof(a) - 1, key);

    byte iv[AES::BLOCKSIZE];
    const unsigned char b[] = "0000000000000000";
    copy(b, b + sizeof(b) - 1, iv);

    const string plain = "Hello World!";

    SECTION("ECB Zero Padding") {
        const string expect = "2E9868AA6EAE72184B4A8881F3DFB26B";
        REQUIRE(expect == ECBEncrypt(plain, key, Z));
    }

    SECTION("ECB PKCS Padding") {
        const string expect = "A1F32C84BE355E41BA350FAFE9B6B001";
        REQUIRE(expect == ECBEncrypt(plain, key, P));
    }

    SECTION("CBC Zero Padding") {
        const string expect = "DDC194E6D0F185AE03A04DD4150435B4";
        REQUIRE(expect == CBCEncrypt(plain, key, iv, Z));
    }

    SECTION("CBC PKCS Padding") {
        const string expect = "817BC015A16257FF845BFA0C4DC2FCBB";
        REQUIRE(expect == CBCEncrypt(plain, key, iv, P));
    }

}

TEST_CASE("Decryption", "[Decryption]") {

    byte key[AES::DEFAULT_KEYLENGTH];
    const unsigned char a[] = "1234567890123456";
    copy(a, a + sizeof(a) - 1, key);

    byte iv[AES::BLOCKSIZE];
    const unsigned char b[] = "0000000000000000";
    copy(b, b + sizeof(b) - 1, iv);

    const string plain = "Hello World!";

    SECTION("ECB Zero Padding") {
        const string cipher = "2E9868AA6EAE72184B4A8881F3DFB26B";
        REQUIRE(plain == ECBDecrypt(cipher, key, Z, true).c_str());
    }

    SECTION("ECB PKCS Padding") {
        const string cipher = "A1F32C84BE355E41BA350FAFE9B6B001";
        REQUIRE(plain == ECBDecrypt(cipher, key, P, true).c_str());
    }

    SECTION("CBC Zero Padding") {
        const string cipher = "DDC194E6D0F185AE03A04DD4150435B4";
        REQUIRE(plain == CBCDecrypt(cipher, key, iv, Z, true).c_str());
    }

    SECTION("CBC PKCS Padding") {
        const string cipher = "817BC015A16257FF845BFA0C4DC2FCBB";
        REQUIRE(plain == CBCDecrypt(cipher, key, iv, P, true).c_str());
    }

}