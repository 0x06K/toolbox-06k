#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef NTSTATUS(WINAPI* PNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// Partial RTL_USER_PROCESS_PARAMETERS (just enough for Environment)
typedef struct _RTL_USER_PROCESS_PARAMETERS_PARTIAL {
    BYTE Reserved1[0x80];
    PVOID Environment;
} RTL_USER_PROCESS_PARAMETERS_PARTIAL;

// Partial PEB struct (just enough to get ProcessParameters)
typedef struct _PEB_PARTIAL {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    PVOID ProcessParameters;
} PEB_PARTIAL;

void EnumeratePEB(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("Failed to open process: %lu\n", GetLastError());
        return;
    }

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    PNtQueryInformationProcess NtQueryInformationProcess = 
        (PNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status = NtQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), NULL);
    if (status != 0) {
        printf("NtQueryInformationProcess failed: 0x%X\n", status);
        CloseHandle(hProcess);
        return;
    }

    // Read the PEB
    PEB_PARTIAL peb = { 0 };
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        printf("Failed to read PEB: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    // Read ProcessParameters
    RTL_USER_PROCESS_PARAMETERS_PARTIAL procParams = { 0 };
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), NULL)) {
        printf("Failed to read ProcessParameters: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    // Read Environment block
    WCHAR envBuffer[32768];  // 32 KB buffer
    if (!ReadProcessMemory(hProcess, procParams.Environment, envBuffer, sizeof(envBuffer), NULL)) {
        printf("Failed to read environment block: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    // Parse environment block (null-terminated pairs)
    WCHAR* ptr = envBuffer;
    while (*ptr) {
        wprintf(L"%s\n", ptr);
        ptr += wcslen(ptr) + 1;
    }

    CloseHandle(hProcess);
}
