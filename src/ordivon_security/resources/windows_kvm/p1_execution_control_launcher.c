#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "p1_execution_control_script.h"

static int write_bytes(const wchar_t *path, const unsigned char *content, DWORD length) {
    HANDLE handle = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        return 1;
    }
    DWORD written = 0;
    BOOL ok = WriteFile(handle, content, length, &written, NULL);
    FlushFileBuffers(handle);
    CloseHandle(handle);
    return (!ok || written != length) ? 2 : 0;
}

static int write_marker(const wchar_t *path) {
    const unsigned char marker[] = "executed\n";
    return write_bytes(path, marker, (DWORD)(sizeof(marker) - 1));
}

static int self_path(wchar_t *output, DWORD count) {
    DWORD length = GetModuleFileNameW(NULL, output, count);
    return length == 0 || length >= count ? 1 : 0;
}

static int powershell_path(wchar_t *output, size_t count) {
    wchar_t system_dir[MAX_PATH];
    UINT length = GetSystemDirectoryW(system_dir, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return 1;
    }
    int result = swprintf(
        output,
        count,
        L"%ls\\WindowsPowerShell\\v1.0\\powershell.exe",
        system_dir
    );
    return result < 0 || (size_t)result >= count ? 2 : 0;
}

static int run_policy_script(const wchar_t *result_path) {
    wchar_t self[MAX_PATH];
    wchar_t powershell[MAX_PATH * 2];
    wchar_t temp_dir[MAX_PATH * 2];
    wchar_t script_path[MAX_PATH * 3];
    wchar_t command[16384];

    if (self_path(self, MAX_PATH) != 0 || powershell_path(powershell, sizeof(powershell) / sizeof(powershell[0])) != 0) {
        return 10;
    }
    DWORD temp_length = GetTempPathW((DWORD)(sizeof(temp_dir) / sizeof(temp_dir[0])), temp_dir);
    if (temp_length == 0 || temp_length >= sizeof(temp_dir) / sizeof(temp_dir[0])) {
        return 11;
    }
    int script_length = swprintf(
        script_path,
        sizeof(script_path) / sizeof(script_path[0]),
        L"%lsordivon-p1-execution-control-%lu.ps1",
        temp_dir,
        (unsigned long)GetCurrentProcessId()
    );
    if (script_length < 0 || (size_t)script_length >= sizeof(script_path) / sizeof(script_path[0])) {
        return 12;
    }
    if (write_bytes(script_path, embedded_script, embedded_script_len) != 0) {
        return 13;
    }

    int command_length = swprintf(
        command,
        sizeof(command) / sizeof(command[0]),
        L"\"%ls\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \"%ls\" -SelfPath \"%ls\" -ResultPath \"%ls\"",
        powershell,
        script_path,
        self,
        result_path
    );
    if (command_length < 0 || (size_t)command_length >= sizeof(command) / sizeof(command[0])) {
        DeleteFileW(script_path);
        return 14;
    }

    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    BOOL created = CreateProcessW(
        powershell,
        command,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &startup,
        &process
    );
    if (!created) {
        DeleteFileW(script_path);
        return 15;
    }
    CloseHandle(process.hThread);
    DWORD waited = WaitForSingleObject(process.hProcess, 60000);
    if (waited != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 90);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hProcess);
        DeleteFileW(script_path);
        return 16;
    }
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(process.hProcess, &exit_code)) {
        CloseHandle(process.hProcess);
        DeleteFileW(script_path);
        return 17;
    }
    CloseHandle(process.hProcess);
    DeleteFileW(script_path);
    return (int)exit_code;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && wcscmp(argv[1], L"--marker") == 0) {
        return write_marker(argv[2]);
    }
    if (argc == 3 && wcscmp(argv[1], L"--result") == 0) {
        return run_policy_script(argv[2]);
    }
    return 64;
}
