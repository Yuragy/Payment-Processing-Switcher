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
#include <procinfo.h> 
#include <sys/procfs.h>

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
    pid_t pid = 0;
    int max_proc = 1024;
    struct procentry64 *procs = new procentry64[max_proc];
    int nprocs = getprocs64(procs, sizeof(procs[0]), NULL, 0, NULL, 0);

    for (int i = 0; i < nprocs; i++) {
        if (strcmp(procs[i].pi_comm, processName.c_str()) == 0) {
            pid = procs[i].pi_pid;
            break;
        }
    }

    delete[] procs;
    return pid;
}

void* getDlopenAddress() {
    void* handle = dlopen("libc.a(shr.o)", RTLD_NOW);
    if (!handle) {
        std::cerr << "Failed to load libc.a(shr.o)" << std::endl;
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

bool injectLibrary(pid_t pid, const char* libPath) {
    if (ptrace(PT_ATTACH, pid, NULL, 0) == -1) {
        std::cerr << "Failed to attach to the process: " << strerror(errno) << std::endl;
        return false;
    }

    waitpid(pid, NULL, 0);

    struct pt_regs regs;
    if (ptrace(PT_GETREGS, pid, NULL, &regs) == -1) {
        std::cerr << "Failed to retrieve the process registers: " << strerror(errno) << std::endl;
        ptrace(PT_DETACH, pid, NULL, 0);
        return false;
    }

    struct pt_regs originalRegs = regs;

    void* dlopenAddr = getDlopenAddress();
    if (dlopenAddr == nullptr) {
        std::cerr << "Failed to get dlopen address" << std::endl;
        ptrace(PT_DETACH, pid, NULL, 0);
        return false;
    }

    size_t libPathLen = strlen(libPath) + 1;

    regs.gpr[3] = 0;
    regs.gpr[4] = libPathLen;
    regs.gpr[5] = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.gpr[6] = MAP_ANONYMOUS | MAP_PRIVATE;
    regs.nip = (unsigned long)mmap;

    if (ptrace(PT_SETREGS, pid, NULL, &regs) == -1) {
        std::cerr << "Failed to set the registers for mmap call: " << strerror(errno) << std::endl;
        ptrace(PT_DETACH, pid, NULL, 0);
        return false;
    }

    if (ptrace(PT_CONTINUE, pid, NULL, 0) == -1) {
        std::cerr << "Failed to continue the process for mmap call: " << strerror(errno) << std::endl;
        ptrace(PT_DETACH, pid, NULL, 0);
        return false;
    }

    waitpid(pid, NULL, 0);

    if (ptrace(PT_GETREGS, pid, NULL, &regs) == -1) {
        std::cerr << "Failed to retrieve process registers after mmap: " << strerror(errno) << std::endl;
        ptrace(PT_DETACH, pid, NULL, 0);
        return false;
    }

    void* remoteLibPath = (void*)regs.gpr[3];

    for (size_t i = 0; i < libPathLen; i += sizeof(long)) {
        long data;
        memcpy(&data, libPath + i, sizeof(long));
        if (ptrace(PT_WRITE_D, pid, remoteLibPath + i, (void*)data) == -1) {
            std::cerr << "Failed to write data to the target process: " << strerror(errno) << std::endl;
            ptrace(PT_DETACH, pid, NULL, 0);
            return false;
        }
    }

    regs.gpr[3] = (unsigned long)remoteLibPath;
    regs.gpr[4] = RTLD_NOW;
    regs.nip = (unsigned long)dlopenAddr;

    if (ptrace(PT_SETREGS, pid, NULL, &regs) == -1) {
        std::cerr << "Failed to set the registers for dlopen call: " << strerror(errno) << std::endl;
        ptrace(PT_DETACH, pid, NULL, 0);
        return false;
    }

    if (ptrace(PT_CONTINUE, pid, NULL, 0) == -1) {
        std::cerr << "Failed to continue the process to call dlopen: " << strerror(errno) << std::endl;
        ptrace(PT_DETACH, pid, NULL, 0);
        return false;
    }

    waitpid(pid, NULL, 0);

    if (ptrace(PT_SETREGS, pid, NULL, &originalRegs) == -1) {
        std::cerr << "Failed to restore the original registers: " << strerror(errno) << std::endl;
        ptrace(PT_DETACH, pid, NULL, 0);
        return false;
    }

    ptrace(PT_DETACH, pid, NULL, 0);
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








