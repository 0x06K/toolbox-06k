#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void EnumerateProcess() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;

    // Take a snapshot of all running processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to take snapshot.\n");
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get the first process in the snapshot
    if (!Process32First(hSnapshot, &pe32)) {
        printf("Failed to retrieve first process.\n");
        CloseHandle(hSnapshot);
        return;
    }
    
    // Header
    printf("+----------------------------------------------------------------------+\n");
    printf("|%-8s %-30s %-8s %-10s %-10s|\n", "PID", "PROCESS NAME", "PPID", "THREADS", "PRIORITY");
    printf("+----------------------------------------------------------------------+\n");
    // Loop through all snapshot
    do {
        // Inside the loop
        printf("|%-8u %-30s %-8u %-10u %-10d|\n",
            pe32.th32ProcessID,
            pe32.szExeFile,
            pe32.th32ParentProcessID,
            pe32.cntThreads,
            pe32.pcPriClassBase);
        
    } while (Process32Next(hSnapshot, &pe32));
    
    printf("+----------------------------------------------------------------------+\n");
    // Cleanup
    CloseHandle(hSnapshot);
}
