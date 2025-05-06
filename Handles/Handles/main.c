#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <wchar.h>
#include "structs.h"

#pragma comment(lib,"ntdll.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

DWORD GetTargetPID(const wchar_t* processName) {
    DWORD processes[1024], needed;

    if (!EnumProcesses(processes, sizeof(processes), &needed)) return 0;

    for (DWORD i = 0; i < needed / sizeof(DWORD); i++) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);

        if (hProcess) {
            wchar_t name[MAX_PATH] = { 0 };
            if (GetModuleBaseNameW(hProcess, NULL, name, MAX_PATH)) {
                if (_wcsicmp(name, processName) == 0) {
                    CloseHandle(hProcess);

                    return processes[i];
                }
            }
            CloseHandle(hProcess);
        }
    }

    return 0;
}

void PrintAccessMask(ACCESS_MASK access) {
    printf("AccessMask: ");

    if (access & DELETE) printf("DELETE ");
    if (access & READ_CONTROL) printf("READ_CONTROL ");
    if (access & WRITE_DAC) printf("WRITE_DAC ");
    if (access & WRITE_OWNER) printf("WRITE_OWNER ");
    if (access & SYNCHRONIZE) printf("SYNCHRONIZE ");

    if (access & GENERIC_READ) printf("GENERIC_READ ");
    if (access & GENERIC_WRITE) printf("GENERIC_WRITE ");
    if (access & GENERIC_EXECUTE) printf("GENERIC_EXECUTE ");
    if (access & GENERIC_ALL) printf("GENERIC_ALL ");

    if (access & ACCESS_SYSTEM_SECURITY) printf("ACCESS_SYSTEM_SECURITY ");
    if (access & MAXIMUM_ALLOWED) printf("MAXIMUM_ALLOWED ");

    if (access == 0) printf("NONE ");

    printf("| ");
}


void PrintHandleName(HANDLE hDupHandle) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!ntdll) {
        printf("[!] ntdll.dll not loaded.\n");
        return;
    }

    NtQueryObject_t NtQueryObject = (NtQueryObject_t)GetProcAddress(ntdll, "NtQueryObject");

    if (!NtQueryObject) {
        printf("[!] NtQueryObject not found.\n");
        return;
    }

    BYTE buffer[1024];
    ULONG len;

    NTSTATUS status = NtQueryObject(hDupHandle, ObjectNameInformation, &buffer, sizeof(buffer), &len);
    if (NT_SUCCESS(status)) {
        POBJECT_NAME_INFORMATION objName = (POBJECT_NAME_INFORMATION)buffer;

        if (objName->Name.Length > 0)
            wprintf(L"Name: %.*s\n", objName->Name.Length / 2, objName->Name.Buffer);
        else
            wprintf(L"Name: (unnamed)\n");
    }
}

void PrintHandleTypeName(HANDLE hDupHandle) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;

    NtQueryObject_t NtQueryObject = (NtQueryObject_t)GetProcAddress(ntdll, "NtQueryObject");
    if (!NtQueryObject) return;

    BYTE buffer[4096];
    ULONG len;

    NTSTATUS status = NtQueryObject(hDupHandle, ObjectTypeInformation, &buffer, sizeof(buffer), &len);

    if (NT_SUCCESS(status)) {
        POBJECT_TYPE_INFORMATION objType = (POBJECT_TYPE_INFORMATION)buffer;
        if (objType->TypeName.Length > 0)
            wprintf(L"Type: %.*s | ", objType->TypeName.Length / 2, objType->TypeName.Buffer);
        else
            wprintf(L"Type: (unknown) | ");
    }
}

int wmain(int argc, const wchar_t* argv[]) {
    if (argc != 2) {
        printf("[!] USAGE: Handles.exe <ProcessName>\n");
        return 1;
    }

    const wchar_t* processname = argv[1];
    DWORD PID = GetTargetPID(processname);

    if (PID == 0) {
        printf("[-] %ws Process Not Found in Your System\n", processname);
        return 1;
    }

    printf("[+] PID: %lu\n", PID);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        printf("[!] Failed to load ntdll.dll\n");
        return 1;
    }

    NtQuerySystemInformation_t NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        printf("[!] Failed to resolve NtQuerySystemInformation\n");
        return 1;
    }

    ULONG size = 0x10000;
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(size);
    if (!handleInfo) {
        printf("[!] Memory allocation failed\n");
        return 1;
    }

    NTSTATUS status;
    while ((status = NtQuerySystemInformation(16 , handleInfo, size, NULL)) == 0xC0000004) {
        size *= 2;
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, size);
        if (!handleInfo) {
            printf("[!] Memory reallocation failed\n");
            return 1;
        }
    }

    if (!NT_SUCCESS(status)) {
        printf("[-] Failed to query system information.\n");
        free(handleInfo);
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, PID);
    if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
        printf("[!] ERROR opening target process. Code: %lu\n", GetLastError());
        free(handleInfo);
        return 1;
    }

    for (ULONG i = 0; i < handleInfo->HandleCount; i++) {
        SYSTEM_HANDLE h = handleInfo->Handles[i];
        if (h.ProcessId != PID)
            continue;

        HANDLE dupHandle = NULL;
        if (DuplicateHandle(hProcess, (HANDLE)(uintptr_t)h.Handle,
            GetCurrentProcess(), &dupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {

            printf("Handle: 0x%04X | ", h.Handle);
            PrintAccessMask(h.GrantedAccess);

            PrintHandleTypeName(dupHandle);

            PrintHandleName(dupHandle);
            
            CloseHandle(dupHandle);
        }

    }

    CloseHandle(hProcess);
    free(handleInfo);

    return 0;
}