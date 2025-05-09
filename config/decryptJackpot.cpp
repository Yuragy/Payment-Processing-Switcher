#include <openssl/aes.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>
#include <iomanip>

const unsigned char FIXED_AES_KEY[] = "Iw2M4P670YaZcdef";
const unsigned char IV[] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
const unsigned char XOR_KEY = 0xAA;

void decryptFile(const std::string& inputFile, const std::string& outputFile) {
    AES_KEY aesKeyStruct;
    AES_set_decrypt_key(FIXED_AES_KEY, 128, &aesKeyStruct); 

    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile.is_open()) {
        std::cerr << "Could not open file for reading." << std::endl;
        return;
    }

    inFile.seekg(0, std::ios::end);
    std::streampos fileSize = inFile.tellg();
    inFile.seekg(0, std::ios::beg);

    if (fileSize == 0) {
        std::cerr << "File is empty." << std::endl;
        inFile.close();
        return;
    }

    std::vector<unsigned char> encryptedBuffer(fileSize);
    inFile.read(reinterpret_cast<char*>(encryptedBuffer.data()), fileSize);
    inFile.close();

    for (size_t i = 0; i < encryptedBuffer.size(); ++i) {
        encryptedBuffer[i] ^= XOR_KEY;
    }

    std::vector<unsigned char> decryptedBuffer(encryptedBuffer.size());
    unsigned char iv[AES_BLOCK_SIZE];
    std::memcpy(iv, IV, AES_BLOCK_SIZE);

    AES_cbc_encrypt(encryptedBuffer.data(), decryptedBuffer.data(), encryptedBuffer.size(), &aesKeyStruct, iv, AES_DECRYPT);

    size_t padding = decryptedBuffer.back();
    decryptedBuffer.resize(decryptedBuffer.size() - padding);

    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Could not open file for writing." << std::endl;
        return;
    }
    outFile.write(reinterpret_cast<const char*>(decryptedBuffer.data()), decryptedBuffer.size());
    outFile.close();

    std::cout << "Decryption complete. Data written to " << outputFile << std::endl;
}

int main() {
    decryptFile("C:\\intels\\Drivers\\spc1234.dat", "C:\\intels\\Drivers\\decrypted_spc1234.dat"); // use real path
    return 0;
}


