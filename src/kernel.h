#ifndef KERNEL_H
#define KERNEL_H

#include <windows.h>
#include <string>
#include <vector>

const ULONG SystemModuleInformation = 11;
const size_t MAX_MODULE_NAME = 256;

struct KernelModule {
    ULONG_PTR baseAddress;
    ULONG size;
    std::string name;
    std::string fullPath;
};

struct RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
};

struct RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
};

// function declarations
ULONG_PTR GetKernelModuleBase(const std::string& moduleName);
std::vector<KernelModule> GetAllKernelModules();
std::string GetModuleName(const KernelModule& module);

// NT API declarations
typedef LONG NTSTATUS;
typedef NTSTATUS (WINAPI *PNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

#endif 