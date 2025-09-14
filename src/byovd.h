#ifndef BYOVD_H
#define BYOVD_H

#include <windows.h>
#include <string>

struct DriverConfig {
    std::string name;
    std::string devicePath;
    DWORD ioctlCode;
};

class BYOVD {
private:
    DriverConfig config;
    SC_HANDLE scManager;
    SC_HANDLE service;
    
    SC_HANDLE CreateDriverService();
    bool UpdateServicePath();

public:
    BYOVD(const DriverConfig& driverConfig);
    ~BYOVD();
    
    bool Initialize();
    bool Start();
    bool Stop();
    bool KillProcess(DWORD pid);
    void Close();
    
    static DriverConfig GetBdApiUtilConfig() {
        return {"BdApiUtil64", "\\\\.\\BdApiUtil", 0x800024B4};
    }
};

#endif 