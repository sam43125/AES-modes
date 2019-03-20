// Reference: http://www.cppblog.com/arthaslee/archive/2010/12/01/135186.html 
// https://blog.csdn.net/weixin_42314534/article/details/81840131
#include <iostream>
#include <aes.h>

//#pragma comment(lib, "cryptlib.lib")

using namespace std;
using namespace CryptoPP;

int main() {

    //AES中使用的固定參數是以類AES中定義的enum數據類型出現的，而不是成員函數或變量
    //因此需要用::符號來索引
    cout << "AES Parameters: " << endl;
    cout << "Algorithm name : " << AES::StaticAlgorithmName() << endl;

    //Crypto++庫中一般用字節數來表示長度，而不是常用的字節數
    cout << "Block size     : " << AES::BLOCKSIZE * 8 << endl;
    cout << "Min key length : " << AES::MIN_KEYLENGTH * 8 << endl;
    cout << "Max key length : " << AES::MAX_KEYLENGTH * 8 << endl;

    //AES中只包含一些固定的數據，而加密解密的功能由AESEncryption和AESDecryption來完成
    //加密過程
    AESEncryption aesEncryptor; //加密器 

    unsigned char aesKey[AES::DEFAULT_KEYLENGTH];  //密鑰
    unsigned char inBlock[AES::BLOCKSIZE] = "123456789";    //要加密的數據塊
    unsigned char outBlock[AES::BLOCKSIZE]; //加密後的密文塊
    unsigned char xorBlock[AES::BLOCKSIZE]; //必須設定為全零

    memset(xorBlock, 0, AES::BLOCKSIZE); //置零

    aesEncryptor.SetKey(aesKey, AES::DEFAULT_KEYLENGTH);  //設定加密密鑰
    aesEncryptor.ProcessAndXorBlock(inBlock, xorBlock, outBlock);  //加密

    //以16進制顯示加密後的數據
    for (int i = 0; i < 16; i++) {
        cout << hex << (int)outBlock[i] << " ";

    }
    cout << endl;

    //解密
    AESDecryption aesDecryptor;
    unsigned char plainText[AES::BLOCKSIZE];

    aesDecryptor.SetKey(aesKey, AES::DEFAULT_KEYLENGTH);
    //細心的朋友注意到這裡的函數不是之前在DES中出現過的：ProcessBlock，
    //而是多了一個Xor。其實，ProcessAndXorBlock也有DES版本。用法跟AES版本差不多。
    //筆者分別在兩份代碼中列出這兩個函數，有興趣的朋友可以自己研究一下有何差異。
    aesDecryptor.ProcessAndXorBlock(outBlock, xorBlock, plainText);


    for (int i = 0; i < 16; i++) {
        cout << plainText[i];
    }
    cout << endl;

    return 0;
}