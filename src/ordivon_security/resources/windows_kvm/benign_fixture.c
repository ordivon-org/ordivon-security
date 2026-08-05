#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static int write_utf8_file(const wchar_t *path, const char *content) {
    HANDLE handle = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        return 1;
    }
    DWORD length = (DWORD)strlen(content);
    DWORD written = 0;
    BOOL ok = WriteFile(handle, content, length, &written, NULL);
    FlushFileBuffers(handle);
    CloseHandle(handle);
    return (!ok || written != length) ? 2 : 0;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && wcscmp(argv[1], L"--child") == 0) {
        return 0;
    }
    if (argc != 3 || wcscmp(argv[1], L"--result") != 0) {
        return 64;
    }

    wchar_t executable[MAX_PATH];
    DWORD executable_length = GetModuleFileNameW(NULL, executable, MAX_PATH);
    if (executable_length == 0 || executable_length >= MAX_PATH) {
        return 65;
    }

    wchar_t command_line[(MAX_PATH * 2) + 32];
    int command_length = swprintf(
        command_line,
        sizeof(command_line) / sizeof(command_line[0]),
        L"\"%ls\" --child",
        executable
    );
    if (command_length < 0) {
        return 66;
    }

    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    BOOL created = CreateProcessW(
        executable,
        command_line,
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
        return 67;
    }

    DWORD wait_result = WaitForSingleObject(process.hProcess, 30000);
    DWORD child_exit_code = 0xFFFFFFFF;
    if (wait_result == WAIT_OBJECT_0) {
        GetExitCodeProcess(process.hProcess, &child_exit_code);
    } else {
        TerminateProcess(process.hProcess, 68);
        WaitForSingleObject(process.hProcess, 5000);
        child_exit_code = 68;
    }
    DWORD child_pid = process.dwProcessId;
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    DWORD parent_pid = GetCurrentProcessId();
    char result[1024];
    int result_length = snprintf(
        result,
        sizeof(result),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.benign-fixture-result\","
        "\"fixtureId\":\"ordivon-benign-v1\",\"parentProcessId\":%lu,"
        "\"childProcessId\":%lu,\"childExitCode\":%lu,"
        "\"networkRequested\":false,\"completed\":%s}\n",
        (unsigned long)parent_pid,
        (unsigned long)child_pid,
        (unsigned long)child_exit_code,
        child_exit_code == 0 ? "true" : "false"
    );
    if (result_length < 0 || result_length >= (int)sizeof(result)) {
        return 69;
    }
    int write_result = write_utf8_file(argv[2], result);
    if (write_result != 0) {
        return 70 + write_result;
    }
    return child_exit_code == 0 ? 0 : 71;
}
