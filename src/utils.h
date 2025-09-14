#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <string>
#include <vector>
#include <tlhelp32.h>

#ifndef SC_MANAGER_CREATE_SERVICE
#define SC_MANAGER_CREATE_SERVICE 0x0002
#endif

#ifndef TH32CS_SNAPPROCESS
#define TH32CS_SNAPPROCESS 0x00000002
#endif

const DWORD MAX_PATH_LEN = 260;

struct ProcessEntry {
    DWORD processID;
    std::string exeFile;
};

std::string GetExecutableDirectory();
std::string GetDriverPath();
std::vector<std::string> GetTargetProcesses();
DWORD GetProcessIdByName(const std::string& processName);
std::vector<ProcessEntry> EnumerateProcesses();

#endif 