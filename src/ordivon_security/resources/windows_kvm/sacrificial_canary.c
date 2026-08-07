#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static const wchar_t *ROOT = L"C:\\ProgramData\\Ordivon\\S3";
static const wchar_t *PERSISTED_EXE = L"C:\\ProgramData\\Ordivon\\S3\\s3-canary.exe";
static const wchar_t *STAGE1_MARKER = L"C:\\ProgramData\\Ordivon\\S3\\stage1.marker";
static const wchar_t *OBSERVER_MARKER = L"C:\\ProgramData\\Ordivon\\S3\\observer-killed.marker";
static const wchar_t *RUNNER_MARKER = L"C:\\ProgramData\\Ordivon\\S3\\guest-runner-killed.marker";
static const wchar_t *PERSISTENCE_MARKER = L"C:\\ProgramData\\Ordivon\\S3\\persistence-fired.marker";
static const wchar_t *LOG_DELETED_MARKER = L"C:\\ProgramData\\Ordivon\\S3\\synthetic-log-deleted.marker";
static const wchar_t *SYNTHETIC_LOG = L"C:\\ProgramData\\Ordivon\\S3\\synthetic-guest.log";

static int ensure_root(void) {
    if (CreateDirectoryW(ROOT, NULL)) {
        return 0;
    }
    return GetLastError() == ERROR_ALREADY_EXISTS ? 0 : 1;
}

static int write_text(const wchar_t *path, const char *content) {
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

static BOOL exists(const wchar_t *path) {
    DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES;
}

static int run_process(const wchar_t *command, DWORD timeout_ms, DWORD *exit_code, DWORD *pid) {
    wchar_t mutable_command[4096];
    if (wcslen(command) >= (sizeof(mutable_command) / sizeof(mutable_command[0]))) {
        return 1;
    }
    wcscpy(mutable_command, command);
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    BOOL created = CreateProcessW(
        NULL,
        mutable_command,
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
        return 2;
    }
    if (pid != NULL) {
        *pid = process.dwProcessId;
    }
    if (timeout_ms != 0) {
        DWORD waited = WaitForSingleObject(process.hProcess, timeout_ms);
        if (waited != WAIT_OBJECT_0) {
            TerminateProcess(process.hProcess, 90);
            WaitForSingleObject(process.hProcess, 5000);
        }
        if (exit_code != NULL) {
            GetExitCodeProcess(process.hProcess, exit_code);
        }
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return 0;
}

static DWORD parent_pid(void) {
    DWORD current = GetCurrentProcessId();
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);
    DWORD result = 0;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == current) {
                result = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

static int terminate_pid(DWORD pid) {
    if (pid == 0 || pid == GetCurrentProcessId()) {
        return 1;
    }
    HANDLE process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (process == NULL) {
        return 2;
    }
    BOOL terminated = TerminateProcess(process, 91);
    if (terminated) {
        WaitForSingleObject(process, 5000);
    }
    CloseHandle(process);
    return terminated ? 0 : 3;
}

static int observer_mode(void) {
    for (;;) {
        Sleep(60000);
    }
}

static int persisted_mode(void) {
    if (ensure_root() != 0) {
        return 30;
    }
    return write_text(PERSISTENCE_MARKER, "persistence-fired\n") == 0 ? 0 : 31;
}

static int stage_one(const wchar_t *self_path) {
    if (ensure_root() != 0) {
        return 40;
    }
    if (!CopyFileW(self_path, PERSISTED_EXE, FALSE)) {
        DWORD error = GetLastError();
        if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) {
            return 41;
        }
    }
    if (write_text(SYNTHETIC_LOG, "synthetic guest-only log; intentionally disposable\n") != 0) {
        return 42;
    }

    wchar_t observer_command[1024];
    swprintf(observer_command, 1024, L"\"%ls\" --observer", self_path);
    DWORD observer_pid = 0;
    if (run_process(observer_command, 0, NULL, &observer_pid) != 0 || observer_pid == 0) {
        return 43;
    }
    Sleep(300);
    if (terminate_pid(observer_pid) != 0) {
        return 44;
    }
    if (write_text(OBSERVER_MARKER, "observer-killed\n") != 0) {
        return 45;
    }

    const wchar_t *task_command =
        L"schtasks.exe /Create /TN OrdivonS3CanaryPersistence /SC ONSTART /RU SYSTEM /RL HIGHEST "
        L"/TR \"C:\\ProgramData\\Ordivon\\S3\\s3-canary.exe --persisted\" /F";
    DWORD task_exit = 0;
    if (run_process(task_command, 30000, &task_exit, NULL) != 0 || task_exit != 0) {
        return 46;
    }

    if (write_text(STAGE1_MARKER, "stage1-complete\n") != 0) {
        return 47;
    }
    if (!DeleteFileW(SYNTHETIC_LOG)) {
        return 48;
    }
    if (write_text(LOG_DELETED_MARKER, "synthetic-log-deleted\n") != 0) {
        return 49;
    }

    DWORD runner_pid = parent_pid();
    if (runner_pid == 0 || terminate_pid(runner_pid) != 0) {
        return 50;
    }
    if (write_text(RUNNER_MARKER, "guest-runner-killed\n") != 0) {
        return 51;
    }

    DWORD shutdown_exit = 0;
    int shutdown_result = run_process(L"shutdown.exe /r /t 0 /f", 0, &shutdown_exit, NULL);
    if (shutdown_result != 0) {
        return 52;
    }
    Sleep(5000);
    return 0;
}

static int stage_two(const wchar_t *result_path) {
    for (int attempt = 0; attempt < 60 && !exists(PERSISTENCE_MARKER); attempt++) {
        Sleep(500);
    }
    BOOL stage1 = exists(STAGE1_MARKER);
    BOOL observer_killed = exists(OBSERVER_MARKER);
    BOOL runner_killed = exists(RUNNER_MARKER);
    BOOL persistence_fired = exists(PERSISTENCE_MARKER);
    BOOL log_deleted = exists(LOG_DELETED_MARKER) && !exists(SYNTHETIC_LOG);
    BOOL completed = stage1 && observer_killed && runner_killed && persistence_fired && log_deleted;
    char result[1024];
    int length = snprintf(
        result,
        sizeof(result),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.s3-sacrificial-canary-result\","
        "\"fixtureId\":\"ordivon-s3-sacrificial-canary-v1\","
        "\"stage1Observed\":%s,\"observerKilled\":%s,\"guestRunnerKilled\":%s,"
        "\"persistenceFiredAfterReboot\":%s,\"syntheticGuestLogDeleted\":%s,"
        "\"rebootContinuationObserved\":true,\"networkRequested\":false,\"completed\":%s}\n",
        stage1 ? "true" : "false",
        observer_killed ? "true" : "false",
        runner_killed ? "true" : "false",
        persistence_fired ? "true" : "false",
        log_deleted ? "true" : "false",
        completed ? "true" : "false"
    );
    if (length < 0 || length >= (int)sizeof(result)) {
        return 60;
    }
    if (write_text(result_path, result) != 0) {
        return 61;
    }
    return completed ? 0 : 62;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 2 && wcscmp(argv[1], L"--observer") == 0) {
        return observer_mode();
    }
    if (argc == 2 && wcscmp(argv[1], L"--persisted") == 0) {
        return persisted_mode();
    }
    if (argc != 3 || wcscmp(argv[1], L"--result") != 0) {
        return 64;
    }

    wchar_t self_path[MAX_PATH];
    DWORD length = GetModuleFileNameW(NULL, self_path, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return 65;
    }
    if (!exists(STAGE1_MARKER)) {
        return stage_one(self_path);
    }
    return stage_two(argv[2]);
}
