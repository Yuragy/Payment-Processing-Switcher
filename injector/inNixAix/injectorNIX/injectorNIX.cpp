#include <iostream>
#include <fstream>
#include <vector>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <cstring>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <limits.h>
#include <errno.h>
#include <signal.h>
#include <sys/mman.h>

void secureDelete(const std::string& filePath) {
    struct stat stat_buf;
    if (stat(filePath.c_str(), &stat_buf) == 0) {
        std::fstream file(filePath, std::ios::in | std::ios::out);
        if (file.is_open()) {
            std::size_t fileSize = stat_buf.st_size;
            std::vector<char> overwriteData(fileSize, 0);
            file.write(overwriteData.data(), fileSize);
            file.flush();
            file.close();
        }
        unlink(filePath.c_str());
    }
}

pid_t getProcessID(const std::string& processName) {
    DIR* dir = opendir("/proc");
    if (!dir) {
        std::cerr << "Failed to open /proc directory: " << strerror(errno) << std::endl;
        return 0;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR) {
            std::string pidDir = entry->d_name;
            if (std::all_of(pidDir.begin(), pidDir.end(), ::isdigit)) {
                std::string cmdPath = "/proc/" + pidDir + "/comm";
                std::ifstream cmdFile(cmdPath);
                std::string cmdLine;
                if (cmdFile && std::getline(cmdFile, cmdLine)) {
                    if (cmdLine == processName) {
                        closedir(dir);
                        return std::stoi(pidDir);
                    }
                }
            }
        }
    }

    closedir(dir);
    return 0;
}

void* getDlopenAddress() {
    void* handle = dlopen("libc.so.6", RTLD_NOW); // В Linux используется libc.so.6
    if (!handle) {
        std::cerr << "Failed to load libc.so.6" << std::endl;
        return nullptr;
    }
    void* dlopenAddr = dlsym(handle, "dlopen");
    dlclose(handle);
    return dlopenAddr;
}

std::string getCurrentDirectory() {
    char buffer[PATH_MAX];
    if (getcwd(buffer, sizeof(buffer)) != NULL) {
        return std::string(buffer);
    } else {
        std::cerr << "Failed to get current directory: " << strerror(errno) << std::endl;
        return "";
    }
}

void* remoteMmap(pid_t pid, size_t size) {
    struct user_regs_struct regs, backup;
    ptrace(PTRACE_GETREGS, pid, nullptr, &backup);  
    regs = backup;
    regs.rdi = 0;  // addr = NULL
    regs.rsi = size;  // length = size
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
    regs.r10 = MAP_ANONYMOUS | MAP_PRIVATE;  // flags
    regs.rax = __NR_mmap;  // вызов mmap
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
    ptrace(PTRACE_CONT, pid, nullptr, nullptr);
    waitpid(pid, nullptr, 0);

    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    void* addr = (void*)regs.rax;
    ptrace(PTRACE_SETREGS, pid, nullptr, &backup);
    return addr;
}
bool writeDataToProcess(pid_t pid, void* remoteAddr, const void* data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        unsigned char byte = *(reinterpret_cast<const unsigned char*>(data) + i);
        if (ptrace(PTRACE_POKETEXT, pid, reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(remoteAddr) + i), (void*)byte) == -1) {
            std::cerr << "Failed to write byte to the target process: " << strerror(errno) << std::endl;
            return false;
        }
    }
    return true;
}

bool injectLibrary(pid_t pid, const char* libPath) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        std::cerr << "Failed to attach to the process: " << strerror(errno) << std::endl;
        return false;
    }

    waitpid(pid, NULL, 0);

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        std::cerr << "Failed to retrieve the process registers: " << strerror(errno) << std::endl;
        ptrace(PTRACE_DETACH, pid, NULL, 0);
        return false;
    }

    struct user_regs_struct originalRegs = regs;

    void* dlopenAddr = getDlopenAddress();
    if (dlopenAddr == nullptr) {
        std::cerr << "Failed to get dlopen address" << std::endl;
        ptrace(PTRACE_DETACH, pid, NULL, 0);
        return false;
    }

    size_t libPathLen = strlen(libPath) + 1;
    void* remoteLibPath = remoteMmap(pid, libPathLen);
    if (remoteLibPath == nullptr) {
        std::cerr << "Failed to allocate memory in the target process" << std::endl;
        ptrace(PTRACE_DETACH, pid, NULL, 0);
        return false;
    }
    if (!writeDataToProcess(pid, remoteLibPath, libPath, libPathLen)) {
        std::cerr << "Failed to write data to the target process." << std::endl;
        ptrace(PTRACE_DETACH, pid, NULL, 0);
        return false;
    }

    regs.rdi = (unsigned long)remoteLibPath;  // Аргумент для dlopen
    regs.rsi = RTLD_NOW;                      // Флаг для dlopen
    regs.rip = (unsigned long)dlopenAddr;     // Адрес dlopen

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1) {
        std::cerr << "Failed to set the registers for dlopen call: " << strerror(errno) << std::endl;
        ptrace(PTRACE_DETACH, pid, NULL, 0);
        return false;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        std::cerr << "Failed to continue the process to call dlopen: " << strerror(errno) << std::endl;
        ptrace(PTRACE_DETACH, pid, NULL, 0);
        return false;
    }

    waitpid(pid, NULL, 0);

    if (ptrace(PTRACE_SETREGS, pid, NULL, &originalRegs) == -1) {
        std::cerr << "Failed to restore the original registers: " << strerror(errno) << std::endl;
        ptrace(PTRACE_DETACH, pid, NULL, 0);
        return false;
    }

    ptrace(PTRACE_DETACH, pid, NULL, 0);
    return true;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <process_name>" << std::endl;
        return 1;
    }

    const char* processName = argv[1];

    std::string currentDir = getCurrentDirectory();
    if (currentDir.empty()) {
        return 1;
    }

    std::string libPath = currentDir + "/renaski.so";

    pid_t pid = getProcessID(processName);
    if (pid == 0) {
        std::cerr << "Failed to find the process: " << processName << std::endl;
        return 1;
    }

    if (injectLibrary(pid, libPath.c_str())) {
        std::cout << "The library has been successfully injected." << std::endl;
        secureDelete(libPath);
    } else {
        std::cerr << "The library injection failed." << std::endl;
        return 1;
    }

    return 0;
}

