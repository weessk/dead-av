#include "kernel.h"
#include <iostream>
#include <algorithm>
#include <cctype>

ULONG_PTR GetKernelModuleBase(const std::string& moduleName) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    
    PNtQuerySystemInformation NtQuerySystemInformation = 
        (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    
    if (!NtQuerySystemInformation) return 0;
    
    ULONG bufferSize = 64 * 1024; // start with 64KB
    std::vector<BYTE> buffer(bufferSize);
    ULONG returnLength = 0;
    
    NTSTATUS status = NtQuerySystemInformation(
        SystemModuleInformation,
        buffer.data(),
        bufferSize,
        &returnLength
    );
    
    if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
        if (returnLength > 0) {
            buffer.resize(returnLength);
            bufferSize = returnLength;
            status = NtQuerySystemInformation(
                SystemModuleInformation,
                buffer.data(),
                bufferSize,
                &returnLength
            );
        }
    }
    
    if (status != 0) {
        std::cerr << "[-] NtQuerySystemInformation failed, status: 0x" << std::hex << status << std::dec << std::endl;
        return 0;
    }
    
    RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)buffer.data();
    
    std::string targetModule = moduleName;
    std::transform(targetModule.begin(), targetModule.end(), targetModule.begin(), ::tolower);
    
    std::cout << "[+] Scanning " << modules->NumberOfModules << " kernel modules for '" << moduleName << "'..." << std::endl;
    
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        const auto& module = modules->Modules[i];
        
        std::string fullPath((char*)module.FullPathName);
        std::string fileName;
        
        if (module.OffsetToFileName < 256) {
            fileName = std::string((char*)module.FullPathName + module.OffsetToFileName);
        } else {
            size_t lastSlash = fullPath.find_last_of('\\');
            if (lastSlash != std::string::npos) {
                fileName = fullPath.substr(lastSlash + 1);
            } else {
                fileName = fullPath;
            }
        }
        
        std::string fileNameLower = fileName;
        std::transform(fileNameLower.begin(), fileNameLower.end(), fileNameLower.begin(), ::tolower);
        
        if (fileNameLower.find(targetModule) != std::string::npos ||
            (targetModule == "ntoskrnl.exe" && fileNameLower.find("ntoskrnl") != std::string::npos)) {
            return (ULONG_PTR)module.ImageBase;
        }
    }
    
    std::cerr << "[-] Kernel module '" << moduleName << "' not found" << std::endl;
    return 0;
}

std::vector<KernelModule> GetAllKernelModules() {
    std::vector<KernelModule> result;
    
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return result;
    
    PNtQuerySystemInformation NtQuerySystemInformation = 
        (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    
    if (!NtQuerySystemInformation) return result;
    
    ULONG bufferSize = 64 * 1024;
    std::vector<BYTE> buffer(bufferSize);
    ULONG returnLength = 0;
    
    NTSTATUS status = NtQuerySystemInformation(
        SystemModuleInformation,
        buffer.data(),
        bufferSize,
        &returnLength
    );
    
    if (status == 0xC0000004) {
        if (returnLength > 0) {
            buffer.resize(returnLength);
            bufferSize = returnLength;
            status = NtQuerySystemInformation(
                SystemModuleInformation,
                buffer.data(),
                bufferSize,
                &returnLength
            );
        }
    }
    
    if (status != 0) return result;
    
    RTL_PROCESS_MODULES* modules = (RTL_PROCESS_MODULES*)buffer.data();
    
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        const auto& module = modules->Modules[i];
        
        KernelModule km;
        km.baseAddress = (ULONG_PTR)module.ImageBase;
        km.size = module.ImageSize;
        km.fullPath = std::string((char*)module.FullPathName);
        
        if (module.OffsetToFileName < 256) {
            km.name = std::string((char*)module.FullPathName + module.OffsetToFileName);
        } else {
            size_t lastSlash = km.fullPath.find_last_of('\\');
            if (lastSlash != std::string::npos) {
                km.name = km.fullPath.substr(lastSlash + 1);
            } else {
                km.name = km.fullPath;
            }
        }
        
        result.push_back(km);
    }
    
    return result;
}

std::string GetModuleName(const KernelModule& module) {
    return module.name;
}