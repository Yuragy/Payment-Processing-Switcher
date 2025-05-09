#include <iostream>
#include <fstream>
#include <string>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>

const unsigned char FIXED_AES_KEY[] = "Iw2M4P670YaZcdef";
const unsigned char IV[] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
const unsigned char XOR_KEY = 0xAA;

void applyXOR(unsigned char* data, int len) {
    for (int i = 0; i < len; ++i) {
        data[i] ^= XOR_KEY;
    }
}

std::string encryptAES(const std::string& plainText) {
    AES_KEY encryptKey;
    AES_set_encrypt_key(FIXED_AES_KEY, 128, &encryptKey);

    int padding = AES_BLOCK_SIZE - (plainText.size() % AES_BLOCK_SIZE);
    std::string paddedText = plainText + std::string(padding, static_cast<char>(padding));

    std::vector<unsigned char> cipherText(paddedText.size());

    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, IV, AES_BLOCK_SIZE);

    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(paddedText.c_str()), cipherText.data(), paddedText.size(), &encryptKey, iv, AES_ENCRYPT);

    applyXOR(cipherText.data(), cipherText.size());

    return std::string(reinterpret_cast<char*>(cipherText.data()), cipherText.size());
}

void createEncryptedIniFile(const std::string& infoFile, const std::string& blkFile, const std::string& iniFile) {
    std::ifstream info(infoFile);
    std::ifstream blk(blkFile);
    std::ofstream ini(iniFile);

    ini << "[info]" << std::endl;
    std::string line;
    while (std::getline(info, line)) {
        ini << encryptAES(line) << std::endl;
    }

    ini << std::endl << "[blk]" << std::endl;
    while (std::getline(blk, line)) {
        ini << encryptAES(line) << std::endl;
    }

    info.close();
    blk.close();
    ini.close();
}

int main() {
    createEncryptedIniFile("info.dat", "blk.dat", "info.ini");
    return 0;
}
