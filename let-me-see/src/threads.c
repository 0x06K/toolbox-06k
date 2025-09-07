#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void EnumerateThreads(DWORD pid) {
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        printf("Failed to create thread snapshot.\n");
        return;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnap, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) { // Only print threads of the target process
                printf("Thread ID         : %lu\n", te32.th32ThreadID);
                printf("Owner Process ID  : %lu\n", te32.th32OwnerProcessID);
                printf("Base Priority     : %ld\n", te32.tpBasePri);
                printf("Delta Priority    : %ld\n", te32.tpDeltaPri);
                printf("------------------------------\n");
            }
        } while (Thread32Next(hThreadSnap, &te32));
    } else {
        printf("Failed to enumerate threads.\n");
    }

    CloseHandle(hThreadSnap);
}
