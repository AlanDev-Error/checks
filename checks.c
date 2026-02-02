#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <psapi.h>
#include <time.h>

#define VERSION "1.0.0"
#define MAX_INPUT 256
#define LOG_FILE "checks.log"
#define MEM_TEST_ITERATIONS 1000
#define MEM_ALLOC_SIZE (1024 * 1024) // 1MB per iteration

// Global flags
volatile int failsafe_triggered = 0;
volatile int exit_requested = 0;
volatile int memory_diagnostic_on = 1;

// Function prototypes
void print_help();
void print_version();
void clear_screen();
void check_exec(const char* filename);
void check_log();
void check_inpath_cmd(const char* cmd);
void check_disk(const char* drive_letter);
void check_memory();
void on_fail();
void save_log(const char* message);
void process_command(const char* input);
DWORD WINAPI keyboard_monitor(LPVOID lpParam);

// Memory diagnostic structure
typedef struct {
    void** allocations;
    int count;
    size_t total_size;
    int failures;
} MemoryDiagnostic;

// Keyboard monitoring thread
DWORD WINAPI keyboard_monitor(LPVOID lpParam) {
    while (!exit_requested) {
        // Check for Ctrl+C
        if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && 
            (GetAsyncKeyState('C') & 0x8000)) {
            if (!failsafe_triggered) {
                failsafe_triggered = 1;
                on_fail();
            }
            Sleep(500); // Debounce
        }
        
        // Check for Ctrl+E
        if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && 
            (GetAsyncKeyState('E') & 0x8000)) {
            if (!exit_requested) {
                exit_requested = 1;
                printf("\n[KEYBOARD] Ctrl+E detected - exiting checks, saving log at %s\n", LOG_FILE);
                save_log("Exit requested via Ctrl+E");
            }
            Sleep(500);
        }
        
        Sleep(100);
    }
    return 0;
}

void on_fail() {
    printf("\n[FAILSAFE] checks FAILSAFE triggered, checking STOPPED\n");
    save_log("FAILSAFE triggered");
    memory_diagnostic_on = 0;
    exit_requested = 1;
}

void save_log(const char* message) {
    FILE* log = fopen(LOG_FILE, "a");
    if (log != NULL) {
        time_t now = time(NULL);
        struct tm* t = localtime(&now);
        fprintf(log, "[%04d-%02d-%02d %02d:%02d:%02d] %s\n",
                t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                t->tm_hour, t->tm_min, t->tm_sec, message);
        fclose(log);
    }
}

void print_help() {
    printf("HELP called, ambulance arriving.\n\n");
    printf("help - Call 'checks' ambulance and prints this screen\n");
    printf("version - print 'VERSION' number\n");
    printf("clear - call the OS's clear cmd\n");
    printf("check exec <filename> - Load and run executable under checks debugger\n");
    printf("check log - prints check log located inside the %s file\n", LOG_FILE);
    printf("check inpath <cmd> - checks the cmd by calling it without full path\n");
    printf("exit - exits\n");
    printf("check disk [drive] - Low-level disk check (default: C:\\)\n");
    printf("check mem - Memory allocation loop with safety protocol\n");
    printf("\nKEY combos:\n");
    printf("ctrl+c - failsafe (stops all checks)\n");
    printf("ctrl+e - exit combo\n");
}

void print_version() {
    printf("VERSION: %s\n", VERSION);
}

void clear_screen() {
    system("cls");
}

// Enhanced executable checker that loads and monitors the process
void check_exec(const char* filename) {
    if (filename == NULL || strlen(filename) == 0) {
        printf("[ERROR] No filename provided. Usage: check exec <filename>\n");
        save_log("check exec - no filename provided");
        return;
    }
    
    printf("[CHECK EXEC] Loading executable: %s\n", filename);
    save_log("check exec started");
    
    // Check if file exists
    DWORD attrib = GetFileAttributesA(filename);
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        printf("[ERROR] File '%s' not found\n", filename);
        save_log("check exec - file not found");
        return;
    }
    
    // Read and validate PE header
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, 
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[ERROR] Cannot open file\n");
        return;
    }
    
    BYTE dosHeader[64];
    DWORD bytesRead;
    ReadFile(hFile, dosHeader, 64, &bytesRead, NULL);
    
    if (bytesRead < 64 || dosHeader[0] != 'M' || dosHeader[1] != 'Z') {
        printf("[ERROR] Invalid PE executable (missing MZ signature)\n");
        CloseHandle(hFile);
        return;
    }
    
    DWORD peOffset = *(DWORD*)(dosHeader + 60);
    printf("[PE HEADER] DOS Header at 0x%p\n", (void*)0);
    printf("[PE HEADER] PE Signature offset: 0x%08X\n", peOffset);
    
    // Read PE signature
    SetFilePointer(hFile, peOffset, NULL, FILE_BEGIN);
    DWORD peSignature;
    ReadFile(hFile, &peSignature, 4, &bytesRead, NULL);
    
    if (peSignature != 0x00004550) { // 'PE\0\0'
        printf("[ERROR] Invalid PE signature\n");
        CloseHandle(hFile);
        return;
    }
    
    printf("[PE HEADER] Valid PE signature found\n");
    
    // Read COFF header
    IMAGE_FILE_HEADER coffHeader;
    ReadFile(hFile, &coffHeader, sizeof(coffHeader), &bytesRead, NULL);
    
    printf("[COFF HEADER] Machine type: 0x%04X\n", coffHeader.Machine);
    printf("[COFF HEADER] Number of sections: %d\n", coffHeader.NumberOfSections);
    printf("[COFF HEADER] Timestamp: %u\n", coffHeader.TimeDateStamp);
    printf("[COFF HEADER] Characteristics: 0x%04X\n", coffHeader.Characteristics);
    
    CloseHandle(hFile);
    
    // Now create the process under debugging
    printf("\n[DEBUGGER] Creating process under checks debugger...\n");
    
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    if (!CreateProcessA(filename, NULL, NULL, NULL, FALSE, 
                       DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                       NULL, NULL, &si, &pi)) {
        printf("[ERROR] Failed to create process (Error: %lu)\n", GetLastError());
        return;
    }
    
    printf("[DEBUGGER] Process created, PID: %lu\n", pi.dwProcessId);
    printf("[DEBUGGER] Thread ID: %lu\n", pi.dwThreadId);
    printf("[DEBUGGER] Process handle: 0x%p\n", pi.hProcess);
    printf("[DEBUGGER] Monitoring execution...\n\n");
    
    DEBUG_EVENT debugEvent;
    DWORD continueStatus = DBG_CONTINUE;
    int eventCount = 0;
    
    while (WaitForDebugEvent(&debugEvent, INFINITE)) {
        eventCount++;
        continueStatus = DBG_CONTINUE;
        
        switch (debugEvent.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                printf("[EVENT %d] CREATE_PROCESS\n", eventCount);
                printf("  Base address: 0x%p\n", debugEvent.u.CreateProcessInfo.lpBaseOfImage);
                printf("  Entry point: 0x%p\n", debugEvent.u.CreateProcessInfo.lpStartAddress);
                CloseHandle(debugEvent.u.CreateProcessInfo.hFile);
                break;
                
            case EXIT_PROCESS_DEBUG_EVENT:
                printf("[EVENT %d] EXIT_PROCESS\n", eventCount);
                printf("  Exit code: %lu\n", debugEvent.u.ExitProcess.dwExitCode);
                ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
                goto debug_done;
                
            case LOAD_DLL_DEBUG_EVENT:
                printf("[EVENT %d] LOAD_DLL\n", eventCount);
                printf("  Base address: 0x%p\n", debugEvent.u.LoadDll.lpBaseOfDll);
                CloseHandle(debugEvent.u.LoadDll.hFile);
                break;
                
            case EXCEPTION_DEBUG_EVENT:
                printf("[EVENT %d] EXCEPTION: 0x%08X\n", eventCount, 
                       debugEvent.u.Exception.ExceptionRecord.ExceptionCode);
                printf("  Address: 0x%p\n", debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
                
                if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                    printf("  Type: Breakpoint\n");
                } else {
                    continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                }
                break;
                
            case CREATE_THREAD_DEBUG_EVENT:
                printf("[EVENT %d] CREATE_THREAD\n", eventCount);
                printf("  Start address: 0x%p\n", debugEvent.u.CreateThread.lpStartAddress);
                break;
                
            case OUTPUT_DEBUG_STRING_EVENT:
                printf("[EVENT %d] DEBUG_STRING\n", eventCount);
                break;
        }
        
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
        
        if (failsafe_triggered) {
            printf("\n[FAILSAFE] Terminating debugged process\n");
            TerminateProcess(pi.hProcess, 1);
            break;
        }
    }
    
debug_done:
    printf("\n[DEBUGGER] Process exited, total events: %d\n", eventCount);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    save_log("check exec completed");
}

void check_log() {
    printf("[CHECK LOG] Reading from %s:\n\n", LOG_FILE);
    FILE* log = fopen(LOG_FILE, "r");
    
    if (log == NULL) {
        printf("[ERROR] No log file found\n");
        return;
    }
    
    char line[512];
    while (fgets(line, sizeof(line), log) != NULL) {
        printf("%s", line);
    }
    
    fclose(log);
}

void check_inpath_cmd(const char* cmd) {
    if (cmd == NULL || strlen(cmd) == 0) {
        printf("[ERROR] No command provided\n");
        return;
    }
    
    printf("[CHECK INPATH] Searching for: %s\n", cmd);
    save_log("check inpath started");
    
    char full_cmd[MAX_INPUT];
    snprintf(full_cmd, sizeof(full_cmd), "where %s", cmd);
    
    int result = system(full_cmd);
    if (result == 0) {
        save_log("check inpath - command found");
    } else {
        printf("[RESULT] Command not found in PATH\n");
        save_log("check inpath - command not found");
    }
}

void check_disk(const char* drive_letter) {
    char drive[8] = "C:\\";
    
    if (drive_letter != NULL && strlen(drive_letter) > 0) {
        // Handle "E:\", "E:", or "E"
        drive[0] = toupper(drive_letter[0]);
        drive[1] = ':';
        drive[2] = '\\';
        drive[3] = '\0';
    }
    
    printf("[CHECK DISK] Analyzing drive: %s\n", drive);
    save_log("check disk started");
    
    // Get drive type
    UINT driveType = GetDriveTypeA(drive);
    if (driveType == DRIVE_NO_ROOT_DIR || driveType == DRIVE_UNKNOWN) {
        printf("[ERROR] Drive %s not accessible\n", drive);
        save_log("check disk - drive not found");
        return;
    }
    
    const char* types[] = {"Unknown", "No Root", "Removable", "Fixed", "Network", "CD-ROM", "RAM"};
    printf("[DISK INFO] Type: %s\n", types[driveType <= 6 ? driveType : 0]);
    
    // Get volume information
    char volumeName[MAX_PATH];
    char fileSystem[MAX_PATH];
    DWORD serialNumber, maxComponentLen, fileSystemFlags;
    
    if (GetVolumeInformationA(drive, volumeName, MAX_PATH, &serialNumber,
                             &maxComponentLen, &fileSystemFlags, fileSystem, MAX_PATH)) {
        printf("[VOLUME] Name: %s\n", volumeName);
        printf("[VOLUME] Serial: %08X\n", serialNumber);
        printf("[VOLUME] File system: %s\n", fileSystem);
    }
    
    // Get space info
    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
    if (!GetDiskFreeSpaceExA(drive, &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
        printf("[ERROR] Cannot read disk space\n");
        return;
    }
    
    printf("[SPACE] Total: %.2f GB\n", totalBytes.QuadPart / (1024.0 * 1024.0 * 1024.0));
    printf("[SPACE] Free: %.2f GB\n", totalFreeBytes.QuadPart / (1024.0 * 1024.0 * 1024.0));
    printf("[SPACE] Used: %.2f GB (%.1f%%)\n", 
           (totalBytes.QuadPart - totalFreeBytes.QuadPart) / (1024.0 * 1024.0 * 1024.0),
           100.0 * (totalBytes.QuadPart - totalFreeBytes.QuadPart) / totalBytes.QuadPart);
    
    // Sector information
    DWORD sectorsPerCluster, bytesPerSector, numberOfFreeClusters, totalNumberOfClusters;
    if (GetDiskFreeSpaceA(drive, &sectorsPerCluster, &bytesPerSector, 
                         &numberOfFreeClusters, &totalNumberOfClusters)) {
        printf("[GEOMETRY] Bytes per sector: %lu\n", bytesPerSector);
        printf("[GEOMETRY] Sectors per cluster: %lu\n", sectorsPerCluster);
        printf("[GEOMETRY] Cluster size: %lu bytes\n", bytesPerSector * sectorsPerCluster);
        printf("[GEOMETRY] Total clusters: %lu\n", totalNumberOfClusters);
        printf("[GEOMETRY] Free clusters: %lu\n", numberOfFreeClusters);
    }
    
    // Perform I/O test
    printf("\n[IO TEST] Starting disk read/write test...\n");
    char testFile[MAX_PATH];
    snprintf(testFile, sizeof(testFile), "%schecks_test.tmp", drive);
    
    HANDLE hFile = CreateFileA(testFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, 
                               CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[IO TEST] Cannot create test file (may need permissions)\n");
    } else {
        char testBuffer[4096];
        memset(testBuffer, 0x55, sizeof(testBuffer));
        DWORD bytesWritten, bytesRead;
        
        // Write test
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        for (int i = 0; i < 256; i++) {
            WriteFile(hFile, testBuffer, sizeof(testBuffer), &bytesWritten, NULL);
        }
        
        QueryPerformanceCounter(&end);
        double writeTime = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
        double writeMBps = (256 * 4096 / (1024.0 * 1024.0)) / writeTime;
        
        printf("[IO TEST] Write: %.2f MB/s (%d KB in %.3f sec)\n", writeMBps, 256 * 4, writeTime);
        
        // Read test
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        QueryPerformanceCounter(&start);
        
        for (int i = 0; i < 256; i++) {
            ReadFile(hFile, testBuffer, sizeof(testBuffer), &bytesRead, NULL);
        }
        
        QueryPerformanceCounter(&end);
        double readTime = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
        double readMBps = (256 * 4096 / (1024.0 * 1024.0)) / readTime;
        
        printf("[IO TEST] Read: %.2f MB/s (%d KB in %.3f sec)\n", readMBps, 256 * 4, readTime);
        printf("[IO TEST] Disk performance: %s\n", 
               (writeMBps > 10 && readMBps > 10) ? "GOOD" : "DEGRADED");
        
        CloseHandle(hFile);
    }
    
    save_log("check disk completed");
}

void check_memory() {
    printf("[CHECK MEM] Starting memory diagnostic with safety protocol\n");
    save_log("check mem started");
    memory_diagnostic_on = 1;
    
    MemoryDiagnostic diag = {0};
    diag.allocations = (void**)malloc(MEM_TEST_ITERATIONS * sizeof(void*));
    
    if (!diag.allocations) {
        printf("[ERROR] Cannot allocate diagnostic structure\n");
        return;
    }
    
    PROCESS_MEMORY_COUNTERS pmc;
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    
    printf("[MEM START] Working set: %.2f MB\n", pmc.WorkingSetSize / (1024.0 * 1024.0));
    printf("[MEM START] Starting allocation loop...\n");
    printf("[PROTOCOL] Safety monitoring active\n");
    printf("[PROTOCOL] Will stop on: memory diagnostic off, allocation failure, or system instability\n\n");
    
    LARGE_INTEGER freq, start;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    for (int i = 0; i < MEM_TEST_ITERATIONS && memory_diagnostic_on && !failsafe_triggered; i++) {
        // Allocate memory
        void* ptr = malloc(MEM_ALLOC_SIZE);
        
        if (ptr == NULL) {
            printf("\n[SAFETY] Allocation failed at iteration %d\n", i);
            printf("[SAFETY] Memory diagnostic stopping to prevent crash\n");
            diag.failures++;
            memory_diagnostic_on = 0;
            break;
        }
        
        // Write to memory to ensure it's actually allocated
        memset(ptr, 0xAA, MEM_ALLOC_SIZE);
        
        diag.allocations[diag.count++] = ptr;
        diag.total_size += MEM_ALLOC_SIZE;
        
        // Get current memory info
        GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
        
        // Print status every 10 iterations
        if (i % 10 == 0) {
            printf("[ITERATION %04d] Allocated: %p | Total: %.2f MB | Working set: %.2f MB | Peak: %.2f MB\n",
                   i, ptr,
                   diag.total_size / (1024.0 * 1024.0),
                   pmc.WorkingSetSize / (1024.0 * 1024.0),
                   pmc.PeakWorkingSetSize / (1024.0 * 1024.0));
        }
        
        // Safety check - if working set is getting too large, stop
        MEMORYSTATUSEX memStat;
        memStat.dwLength = sizeof(memStat);
        GlobalMemoryStatusEx(&memStat);
        
        if (memStat.dwMemoryLoad > 90) {
            printf("\n[SAFETY] System memory load at %lu%%\n", memStat.dwMemoryLoad);
            printf("[SAFETY] Stopping to prevent system instability\n");
            memory_diagnostic_on = 0;
            break;
        }
        
        // Check for memory leaks by comparing allocated vs reported
        size_t expected_size = diag.total_size;
        size_t actual_size = pmc.WorkingSetSize;
        
        if (actual_size > expected_size * 2) {
            printf("\n[SAFETY] Possible memory leak detected\n");
            printf("[SAFETY] Expected: %.2f MB, Actual: %.2f MB\n",
                   expected_size / (1024.0 * 1024.0),
                   actual_size / (1024.0 * 1024.0));
            memory_diagnostic_on = 0;
            break;
        }
        
        Sleep(10); // Small delay to prevent overwhelming the system
    }
    
    LARGE_INTEGER end;
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    
    printf("\n[MEM TEST] Completed in %.2f seconds\n", elapsed);
    printf("[MEM TEST] Total iterations: %d\n", diag.count);
    printf("[MEM TEST] Total allocated: %.2f MB\n", diag.total_size / (1024.0 * 1024.0));
    printf("[MEM TEST] Failures: %d\n", diag.failures);
    
    // Cleanup
    printf("\n[CLEANUP] Freeing all allocated memory...\n");
    for (int i = 0; i < diag.count; i++) {
        free(diag.allocations[i]);
        if (i % 100 == 0) {
            printf("[CLEANUP] Freed %d/%d allocations\n", i, diag.count);
        }
    }
    free(diag.allocations);
    
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    printf("[CLEANUP] Final working set: %.2f MB\n", pmc.WorkingSetSize / (1024.0 * 1024.0));
    printf("[RESULT] Memory diagnostic: %s\n", 
           (diag.failures == 0 && memory_diagnostic_on) ? "PASSED" : "STOPPED");
    
    save_log(diag.failures == 0 ? "check mem - PASSED" : "check mem - STOPPED");
}

void process_command(const char* input) {
    char cmd[MAX_INPUT];
    strncpy(cmd, input, MAX_INPUT - 1);
    cmd[MAX_INPUT - 1] = '\0';
    
    // Convert to lowercase for comparison
    char cmd_lower[MAX_INPUT];
    for (int i = 0; cmd[i]; i++) {
        cmd_lower[i] = tolower(cmd[i]);
    }
    cmd_lower[strlen(cmd)] = '\0';
    
    if (strcmp(cmd_lower, "help") == 0) {
        print_help();
    }
    else if (strcmp(cmd_lower, "version") == 0) {
        print_version();
    }
    else if (strcmp(cmd_lower, "clear") == 0) {
        clear_screen();
    }
    else if (strcmp(cmd_lower, "exit") == 0) {
        printf("exiting checks, saving log at %s\n", LOG_FILE);
        save_log("Normal exit");
        exit_requested = 1;
    }
    else if (strncmp(cmd_lower, "check exec", 10) == 0) {
        const char* filename = cmd + 10;
        while (*filename == ' ') filename++;
        check_exec(filename);
    }
    else if (strcmp(cmd_lower, "check log") == 0) {
        check_log();
    }
    else if (strncmp(cmd_lower, "check inpath", 12) == 0) {
        const char* command = cmd + 12;
        while (*command == ' ') command++;
        check_inpath_cmd(command);
    }
    else if (strncmp(cmd_lower, "check disk", 10) == 0) {
        const char* drive = cmd + 10;
        while (*drive == ' ') drive++;
        check_disk(strlen(drive) > 0 ? drive : NULL);
    }
    else if (strcmp(cmd_lower, "check mem") == 0) {
        check_memory();
    }
    else if (strlen(cmd_lower) > 0) {
        printf("Unknown command: %s\nType 'help' for available commands.\n", cmd);
    }
}

int main() {
    printf("checks v%s\n", VERSION);
    printf("\nNote: type 'help' into shell for commands.\n");
    
    save_log("checks started");
    
    // Create keyboard monitoring thread
    HANDLE hThread = CreateThread(NULL, 0, keyboard_monitor, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[WARNING] Could not create keyboard monitor thread\n");
    }
    
    char input[MAX_INPUT];
    
    while (!exit_requested && !failsafe_triggered) {
        printf(">>> ");
        fflush(stdout);
        
        if (fgets(input, MAX_INPUT, stdin) == NULL) {
            break;
        }
        
        input[strcspn(input, "\n")] = 0;
        
        if (!exit_requested && !failsafe_triggered) {
            process_command(input);
        }
    }
    
    if (hThread != NULL) {
        WaitForSingleObject(hThread, 1000);
        CloseHandle(hThread);
    }
    
    return failsafe_triggered ? 1 : 0;
}
