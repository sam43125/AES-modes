// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp aes-modes.cpp -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp aes-modes.cpp -lcryptopp -lpthread

#include <fstream>
using std::ofstream;
using std::endl;

#include <string>
using std::string;

#include <algorithm>
using std::copy;

#include <cryptopp/modes.h>
using CryptoPP::ECB_Mode;
using CryptoPP::CBC_Mode;

#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

using CryptoPP::byte;

enum Padding {
    Z, P
};

const string ECBEncrypt(const string& plain, const byte* key, Padding p) {
    string cipher, encoded;
    ECB_Mode<AES>::Encryption e(key, AES::DEFAULT_KEYLENGTH);
    StringSource(plain, true,
        new StreamTransformationFilter(
            e,
            new StringSink(cipher),
            p == Z ?
            StreamTransformationFilter::ZEROS_PADDING : StreamTransformationFilter::PKCS_PADDING
        )
    );
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded),
            p == Z ?
            StreamTransformationFilter::ZEROS_PADDING : StreamTransformationFilter::PKCS_PADDING
        )
    );
    return encoded;
}

const string ECBDecrypt(const string& cipher, const byte* key, Padding p, bool isHex = false) {
    string recovered;
    ECB_Mode<AES>::Decryption d(key, AES::DEFAULT_KEYLENGTH);
    if (isHex) {
        StringSource(cipher, true,
            new HexDecoder(
                new StreamTransformationFilter(
                    d,
                    new StringSink(recovered),
                    p == Z ?
                    StreamTransformationFilter::ZEROS_PADDING : StreamTransformationFilter::PKCS_PADDING
                )
            )
        );
    }
    else {
        StringSource(cipher, true,
            new StreamTransformationFilter(
                d,
                new StringSink(recovered),
                p == Z ?
                StreamTransformationFilter::ZEROS_PADDING : StreamTransformationFilter::PKCS_PADDING
            )
        );
    }
    return recovered;
}

const string CBCEncrypt(const string& plain, const byte* key, const byte* iv, Padding p) {
    string cipher, encoded;
    CBC_Mode<AES>::Encryption e(key, AES::DEFAULT_KEYLENGTH, iv);
    StringSource(plain, true,
        new StreamTransformationFilter(
            e,
            new StringSink(cipher),
            p == Z ?
            StreamTransformationFilter::ZEROS_PADDING : StreamTransformationFilter::PKCS_PADDING
        )  
    );
    StringSource(cipher, true,
        new HexEncoder(
            new StringSink(encoded), 
            p == Z ?
            StreamTransformationFilter::ZEROS_PADDING : StreamTransformationFilter::PKCS_PADDING
        )
    );
    return encoded;
}

const string CBCDecrypt(const string& cipher, const byte* key, const byte* iv, Padding p, bool isHex = false) {
    string recovered;
    CBC_Mode<AES>::Decryption d(key, AES::DEFAULT_KEYLENGTH, iv);
    if (isHex) {
        StringSource(cipher, true,
            new HexDecoder(
                new StreamTransformationFilter(
                    d,
                    new StringSink(recovered),
                    p == Z ?
                    StreamTransformationFilter::ZEROS_PADDING : StreamTransformationFilter::PKCS_PADDING
                )
            )
        );
    }
    else{
        StringSource(cipher, true,
            new StreamTransformationFilter(
                d,
                new StringSink(recovered),
                p == Z ?
                StreamTransformationFilter::ZEROS_PADDING : StreamTransformationFilter::PKCS_PADDING
            )
        );
    }
    return recovered;
}


#ifndef NO_MAIN

int main(int argc, char* argv[]) {

    ofstream fout("Out.txt");

    byte key[AES::DEFAULT_KEYLENGTH];
    const unsigned char a[] = "1234567890123456";
    copy(a, a + sizeof(a) - 1, key);

    byte iv[AES::BLOCKSIZE];
    const unsigned char b[] = "0000000000000000";
    copy(b, b + sizeof(b) - 1, iv);

    const string plain = "AES is efficient in both software and hardware.";
    // 41455320697320656666696369656e7420696e20626f746820736f66747761726520616e642068617264776172652e
    string encoded;

    encoded = ECBEncrypt(plain, key, Z);
    fout << encoded.c_str() << endl << endl;

    encoded = ECBEncrypt(plain, key, P);
    fout << encoded.c_str() << endl << endl;

    encoded = CBCEncrypt(plain, key, iv, Z);
    fout << encoded.c_str() << endl << endl;

    encoded = CBCEncrypt(plain, key, iv, P);
    fout << encoded.c_str() << endl << endl;

    fout.close();
    return 0;
}

#endif