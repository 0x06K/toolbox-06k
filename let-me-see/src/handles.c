#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// --- Definitions ---
typedef LONG NTSTATUS;
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemHandleInformation 16

typedef struct _SYSTEM_HANDLE {
    DWORD       ProcessId;
    BYTE        ObjectTypeNumber;
    BYTE        Flags;
    USHORT      Handle;
    PVOID       Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1]; // Variable length
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// --- NtQuerySystemInformation declaration ---
typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// --- Main Logic ---
void EnumerateHandles(DWORD targetPID) {
    // Load NtQuerySystemInformation from ntdll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("Failed to load ntdll.dll\n");
        return;
    }

    PNtQuerySystemInformation NtQuerySystemInformation =
        (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        printf("Failed to get NtQuerySystemInformation\n");
        return;
    }

    // Allocate and grow buffer as needed
    ULONG bufferSize = 0x10000;
    PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;
    NTSTATUS status;
    do {
        free(handleInfo);
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);
        if (!handleInfo) {
            printf("Memory allocation failed\n");
            return;
        }
        status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, bufferSize, NULL);
        bufferSize *= 2;
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status != 0) {
        printf("NtQuerySystemInformation failed (status: 0x%X)\n", status);
        free(handleInfo);
        return;
    }

    printf("Handles for PID: %lu\n\n", targetPID);

    ULONG matchCount = 0;

    for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
        SYSTEM_HANDLE h = handleInfo->Handles[i];
        if (h.ProcessId == targetPID) {
            printf("Handle #%lu\n", ++matchCount);
            printf("  Handle Value  : 0x%04X\n", h.Handle);
            printf("  Object Ptr    : 0x%p\n", h.Object);
            printf("  Access Rights : 0x%08X\n", h.GrantedAccess);
            printf("  Type Number   : %u\n", h.ObjectTypeNumber);
            printf("  Flags         : 0x%02X\n", h.Flags);
            printf("------------------------------------\n");
        }
    }

    if (matchCount == 0) {
        printf("No handles found for this process.\n");
    }

    free(handleInfo);
}