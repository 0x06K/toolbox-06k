#include <windows.h>
#include <stdio.h>
#include <sddl.h>
#include <tchar.h>

void EnumerateSidAndName(PSID sid) {
    char name[256], domain[256];
    DWORD cchName = sizeof(name);
    DWORD cchDomain = sizeof(domain);
    SID_NAME_USE sidType;

    if (LookupAccountSidA(NULL, sid, name, &cchName, domain, &cchDomain, &sidType)) {
        printf("%s\\%s", domain, name);
    } else {
        // Fallback: print SID string if name lookup fails
        LPSTR sidString = NULL;
        if (ConvertSidToStringSidA(sid, &sidString)) {
            printf("%s", sidString);
            LocalFree(sidString);
        } else {
            printf("Unknown SID");
        }
    }
}

void EnumerateTokenUser(HANDLE hToken) {
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
    if (!pTokenUser) return;

    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        printf("User: ");
        EnumerateSidAndName(pTokenUser->User.Sid);
        printf("\n");
    }
    free(pTokenUser);
}

void EnumerateTokenGroups(HANDLE hToken) {
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &dwSize);
    PTOKEN_GROUPS pGroups = (PTOKEN_GROUPS)malloc(dwSize);
    if (!pGroups) return;

    if (GetTokenInformation(hToken, TokenGroups, pGroups, dwSize, &dwSize)) {
        printf("Groups:\n");
        for (DWORD i = 0; i < pGroups->GroupCount; i++) {
            printf("  - ");
            EnumerateSidAndName(pGroups->Groups[i].Sid);
            if (pGroups->Groups[i].Attributes & SE_GROUP_ENABLED) {
                printf(" [Enabled]");
            }
            printf("\n");
        }
    }
    free(pGroups);
}

void EnumerateTokenPrivileges(HANDLE hToken) {
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
    PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)malloc(dwSize);
    if (!pPrivs) return;

    if (GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize)) {
        printf("Privileges:\n");
        for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
            LUID_AND_ATTRIBUTES la = pPrivs->Privileges[i];
            char name[256];
            DWORD nameLen = sizeof(name);
            if (LookupPrivilegeNameA(NULL, &la.Luid, name, &nameLen)) {
                printf("  - %s", name);
                if (la.Attributes & SE_PRIVILEGE_ENABLED) {
                    printf(" [Enabled]");
                }
                printf("\n");
            }
        }
    }
    free(pPrivs);
}

void EnumerateTokens(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        printf("OpenProcess failed for PID %lu (Error %lu)\n", pid, GetLastError());
        return;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        printf("OpenProcessToken failed (Error %lu)\n", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    EnumerateTokenUser(hToken);
    EnumerateTokenGroups(hToken);
    EnumerateTokenPrivileges(hToken);

    CloseHandle(hToken);
    CloseHandle(hProcess);
}