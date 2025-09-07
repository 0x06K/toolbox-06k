#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void EnumerateHeap(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
        return;
    }

    HEAPLIST32 hl;
    hl.dwSize = sizeof(HEAPLIST32);

    if (Heap32ListFirst(hSnapshot, &hl)) {
        do {
            printf("Heap ID: 0x%08lx, Process ID: %lu\n", hl.th32HeapID, hl.th32ProcessID);

            HEAPENTRY32 he;
            he.dwSize = sizeof(HEAPENTRY32);
            if (Heap32First(&he, pid, hl.th32HeapID)) {
                do {
                    printf("  Block: Addr=0x%p, Size=%lu, Flags=0x%lx\n",
                           he.dwAddress, he.dwBlockSize, he.dwFlags);
                } while (Heap32Next(&he));
            }

        } while (Heap32ListNext(hSnapshot, &hl));
    } else {
        printf("Heap32ListFirst failed. Error: %lu\n", GetLastError());
    }

    CloseHandle(hSnapshot);
}
