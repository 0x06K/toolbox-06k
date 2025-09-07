#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <windows.h>
#include <ctype.h>

// Function declarations
void EnumeratePEB(DWORD pid);
void EnumerateThreads(DWORD pid);
void EnumerateModules(DWORD pid);
void EnumerateHeap(DWORD PID);
void EnumerateHandles(DWORD PID);
void EnumerateProcess();
void EnumerateTokens(DWORD PID);
void show_help();
void to_lowercase(char *str);

int main() {
    char input[256];
    DWORD PID = 1234;  // Default PID
    bool running = true;

    printf("<=== LET ME SEE ^_^ ===>\n");
    printf("Type 'help' to see available commands.\n");

    while (running) {
        printf("cli> ");
        if (fgets(input, sizeof(input), stdin) == NULL) break;
        input[strcspn(input, "\n")] = 0;  // Remove newline
        to_lowercase(input);             // Convert to lowercase

        // Tokenize input for command and argument
        char *cmd = strtok(input, " ");
        char *arg = strtok(NULL, " ");

        if (!cmd) continue;

        // Handle commands
        if (strcmp(cmd, "peb") == 0) {
            EnumeratePEB(PID);
        } else if (strcmp(cmd, "threads") == 0) {
            EnumerateThreads(PID);
        } else if (strcmp(cmd, "modules") == 0) {
            EnumerateModules(PID);
        } else if (strcmp(cmd, "heap") == 0) {
            EnumerateHeap(PID);
        } else if (strcmp(cmd, "handles") == 0) {
            EnumerateHandles(PID);
        } else if (strcmp(cmd, "process") == 0) {
            EnumerateProcess();
        } else if (strcmp(cmd, "tokens") == 0) {
            EnumerateTokens(PID);
        } else if (strcmp(cmd, "set") == 0 && arg && strcmp(arg, "pid") == 0) {
            char *pid_val = strtok(NULL, " ");
            if (pid_val) {
                PID = (DWORD)atoi(pid_val);
                printf("[+] PID set to %lu\n", PID);
            } else {
                printf("[-] Usage: set pid <value>\n");
            }
        } else if (strcmp(cmd, "show") == 0 && arg && strcmp(arg, "pid") == 0) {
            printf("[*] Current PID: %lu\n", PID);
        } else if (strcmp(cmd, "help") == 0) {
            show_help();
        } else if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) {
            running = false;
        } else {
            printf("Unknown command. Type 'help' to see available commands.\n");
        }
    }

    printf("Goodbye!\n");
    return 0;
}

// Convert input into smaller case
void to_lowercase(char *str) {
    for (int i = 0; str[i]; i++) {
        str[i] = (char)tolower((unsigned char)str[i]);
    }
}
// Help Menu
void show_help() {
    printf("Available commands:\n");
    printf("  set pid <value>  - Set the target PID\n");
    printf("  show pid         - Show current target PID\n");
    printf("  peb              - Enumerate PEB of PID\n");
    printf("  threads          - Enumerate threads of PID\n");
    printf("  modules          - Enumerate modules of PID\n");
    printf("  heap             - Analyze heap of current process\n");
    printf("  handles          - List open handles\n");
    printf("  process          - Enumerate processes\n");
    printf("  tokens           - Enumerate access tokens\n");
    printf("  help             - Show this help menu\n");
    printf("  exit             - Exit the CLI\n");
}

