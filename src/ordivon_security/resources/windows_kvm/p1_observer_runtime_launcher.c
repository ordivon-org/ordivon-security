#include <windows.h>
#include <stdio.h>
#include <wchar.h>

#include "p1_observer_runtime_script.h"

static int write_bytes(const wchar_t *path, const unsigned char *content, DWORD length) {
    HANDLE handle = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    BOOL ok;
    if (handle == INVALID_HANDLE_VALUE) return 1;
    ok = WriteFile(handle, content, length, &written, NULL);
    if (ok) ok = FlushFileBuffers(handle);
    CloseHandle(handle);
    return (!ok || written != length) ? 2 : 0;
}

static int powershell_path(wchar_t *output, size_t count) {
    wchar_t system_dir[MAX_PATH];
    UINT length = GetSystemDirectoryW(system_dir, MAX_PATH);
    int result;
    if (length == 0 || length >= MAX_PATH) return 1;
    result = swprintf(
        output,
        count,
        L"%ls\\WindowsPowerShell\\v1.0\\powershell.exe",
        system_dir
    );
    return result < 0 || (size_t)result >= count ? 2 : 0;
}

static int run_probe(const wchar_t *result_path) {
    wchar_t powershell[MAX_PATH * 2];
    wchar_t temp_dir[MAX_PATH * 2];
    wchar_t script_path[MAX_PATH * 3];
    wchar_t command[16384];
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    DWORD temp_length;
    DWORD waited;
    DWORD exit_code = 0;
    int script_length;
    int command_length;

    if (powershell_path(powershell, ARRAYSIZE(powershell)) != 0) return 10;
    temp_length = GetTempPathW(ARRAYSIZE(temp_dir), temp_dir);
    if (temp_length == 0 || temp_length >= ARRAYSIZE(temp_dir)) return 11;
    script_length = swprintf(
        script_path,
        ARRAYSIZE(script_path),
        L"%lsordivon-p1-observer-runtime-%lu.ps1",
        temp_dir,
        (unsigned long)GetCurrentProcessId()
    );
    if (script_length < 0 || (size_t)script_length >= ARRAYSIZE(script_path)) return 12;
    if (write_bytes(script_path, embedded_script, embedded_script_len) != 0) return 13;

    command_length = swprintf(
        command,
        ARRAYSIZE(command),
        L"\"%ls\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        L"-File \"%ls\" -ResultPath \"%ls\"",
        powershell,
        script_path,
        result_path
    );
    if (command_length < 0 || (size_t)command_length >= ARRAYSIZE(command)) {
        DeleteFileW(script_path);
        return 14;
    }
    startup.cb = sizeof(startup);
    if (!CreateProcessW(
            powershell,
            command,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &startup,
            &process)) {
        DeleteFileW(script_path);
        return 15;
    }
    CloseHandle(process.hThread);
    waited = WaitForSingleObject(process.hProcess, 120000);
    if (waited != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 90);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hProcess);
        DeleteFileW(script_path);
        return 16;
    }
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
    if (argc == 3 && wcscmp(argv[1], L"--result") == 0) {
        return run_probe(argv[2]);
    }
    return 64;
}
