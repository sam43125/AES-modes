// Reference: http://www.cppblog.com/arthaslee/archive/2010/12/01/135186.html 
// https://blog.csdn.net/weixin_42314534/article/details/81840131
#include <iostream>
#include <aes.h>

//#pragma comment(lib, "cryptlib.lib")

using namespace std;
using namespace CryptoPP;

int main() {

    //AES���ϥΪ��T�w�ѼƬO�H��AES���w�q��enum�ƾ������X�{���A�Ӥ��O������Ʃ��ܶq
    //�]���ݭn��::�Ÿ��ӯ���
    cout << "AES Parameters: " << endl;
    cout << "Algorithm name : " << AES::StaticAlgorithmName() << endl;

    //Crypto++�w���@��Φr�`�ƨӪ�ܪ��סA�Ӥ��O�`�Ϊ��r�`��
    cout << "Block size     : " << AES::BLOCKSIZE * 8 << endl;
    cout << "Min key length : " << AES::MIN_KEYLENGTH * 8 << endl;
    cout << "Max key length : " << AES::MAX_KEYLENGTH * 8 << endl;

    //AES���u�]�t�@�ǩT�w���ƾڡA�ӥ[�K�ѱK���\���AESEncryption�MAESDecryption�ӧ���
    //�[�K�L�{
    AESEncryption aesEncryptor; //�[�K�� 

    unsigned char aesKey[AES::DEFAULT_KEYLENGTH];  //�K�_
    unsigned char inBlock[AES::BLOCKSIZE] = "123456789";    //�n�[�K���ƾڶ�
    unsigned char outBlock[AES::BLOCKSIZE]; //�[�K�᪺�K���
    unsigned char xorBlock[AES::BLOCKSIZE]; //�����]�w�����s

    memset(xorBlock, 0, AES::BLOCKSIZE); //�m�s

    aesEncryptor.SetKey(aesKey, AES::DEFAULT_KEYLENGTH);  //�]�w�[�K�K�_
    aesEncryptor.ProcessAndXorBlock(inBlock, xorBlock, outBlock);  //�[�K

    //�H16�i����ܥ[�K�᪺�ƾ�
    for (int i = 0; i < 16; i++) {
        cout << hex << (int)outBlock[i] << " ";

    }
    cout << endl;

    //�ѱK
    AESDecryption aesDecryptor;
    unsigned char plainText[AES::BLOCKSIZE];

    aesDecryptor.SetKey(aesKey, AES::DEFAULT_KEYLENGTH);
    //�Ӥߪ��B�ͪ`�N��o�̪���Ƥ��O���e�bDES���X�{�L���GProcessBlock�A
    //�ӬO�h�F�@��Xor�C���AProcessAndXorBlock�]��DES�����C�Ϊk��AES�����t���h�C
    //���̤��O�b����N�X���C�X�o��Ө�ơA�����쪺�B�ͥi�H�ۤv��s�@�U����t���C
    aesDecryptor.ProcessAndXorBlock(outBlock, xorBlock, plainText);


    for (int i = 0; i < 16; i++) {
        cout << plainText[i];
    }
    cout << endl;

    return 0;
}