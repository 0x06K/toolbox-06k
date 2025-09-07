#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void EnumerateModules(DWORD pid) {
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        printf("Failed to take module snapshot.\n");
        return;
    }

    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hModuleSnap, &me32)) {
        do {
            printf("--------------------------------------------------\n");
            printf("Module Name     : %s\n", me32.szModule);
            printf("Executable Path : %s\n", me32.szExePath);
            printf("Base Address    : 0x%p\n", me32.modBaseAddr);
            printf("Module Size     : %lu bytes\n", me32.modBaseSize);
            printf("Handle Address  : 0x%p\n", (void*)&me32.hModule);
            printf("Process ID      : %lu\n", me32.th32ProcessID);
        } while (Module32Next(hModuleSnap, &me32));
    } else {
        printf("Failed to enumerate modules.\n");
    }
    printf("--------------------------------------------------\n");
    CloseHandle(hModuleSnap);
}
