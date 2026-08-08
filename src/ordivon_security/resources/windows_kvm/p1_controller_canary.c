#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

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
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static int sibling_path(const wchar_t *base, const wchar_t *suffix, wchar_t *output, size_t count) {
    int result = swprintf(output, count, L"%ls%ls", base, suffix);
    return result < 0 || (size_t)result >= count ? 1 : 0;
}

static int self_path(wchar_t *output, DWORD count) {
    DWORD length = GetModuleFileNameW(NULL, output, count);
    return length == 0 || length >= count ? 1 : 0;
}

static int build_command(
    const wchar_t *self,
    const wchar_t *mode,
    const wchar_t *argument,
    wchar_t *output,
    size_t count
) {
    int length = swprintf(output, count, L"\"%ls\" %ls \"%ls\"", self, mode, argument);
    return length < 0 || (size_t)length >= count ? 1 : 0;
}

static HANDLE create_job(DWORD active_process_limit) {
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (job == NULL) {
        return NULL;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = {0};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (active_process_limit > 0) {
        limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = active_process_limit;
    }
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        CloseHandle(job);
        return NULL;
    }
    return job;
}

static int spawn_suspended_in_job(
    HANDLE job,
    const wchar_t *self,
    const wchar_t *mode,
    const wchar_t *argument,
    PROCESS_INFORMATION *process
) {
    wchar_t command[8192];
    if (build_command(self, mode, argument, command, sizeof(command) / sizeof(command[0])) != 0) {
        return 1;
    }
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    ZeroMemory(process, sizeof(*process));
    if (!CreateProcessW(
            self,
            command,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW | CREATE_SUSPENDED,
            NULL,
            NULL,
            &startup,
            process)) {
        return 2;
    }
    if (!AssignProcessToJobObject(job, process->hProcess)) {
        TerminateProcess(process->hProcess, 91);
        WaitForSingleObject(process->hProcess, 5000);
        CloseHandle(process->hThread);
        CloseHandle(process->hProcess);
        ZeroMemory(process, sizeof(*process));
        return 3;
    }
    if (ResumeThread(process->hThread) == (DWORD)-1) {
        TerminateProcess(process->hProcess, 92);
        WaitForSingleObject(process->hProcess, 5000);
        CloseHandle(process->hThread);
        CloseHandle(process->hProcess);
        ZeroMemory(process, sizeof(*process));
        return 4;
    }
    CloseHandle(process->hThread);
    process->hThread = NULL;
    return 0;
}

static int spawn_process(
    const wchar_t *self,
    const wchar_t *mode,
    const wchar_t *argument,
    PROCESS_INFORMATION *process
) {
    wchar_t command[8192];
    if (build_command(self, mode, argument, command, sizeof(command) / sizeof(command[0])) != 0) {
        return 1;
    }
    STARTUPINFOW startup = {0};
    startup.cb = sizeof(startup);
    ZeroMemory(process, sizeof(*process));
    if (!CreateProcessW(
            self,
            command,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &startup,
            process)) {
        return 2;
    }
    CloseHandle(process->hThread);
    process->hThread = NULL;
    return 0;
}

static BOOL wait_success(HANDLE process, DWORD timeout_ms, DWORD *exit_code) {
    DWORD waited = WaitForSingleObject(process, timeout_ms);
    if (waited != WAIT_OBJECT_0) {
        return FALSE;
    }
    DWORD code = STILL_ACTIVE;
    if (!GetExitCodeProcess(process, &code)) {
        return FALSE;
    }
    if (exit_code != NULL) {
        *exit_code = code;
    }
    return code == 0;
}

static DWORD job_total_processes(HANDLE job) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = {0};
    if (!QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &accounting,
            sizeof(accounting),
            NULL)) {
        return 0;
    }
    return accounting.TotalProcesses;
}

static DWORD job_active_processes(HANDLE job) {
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting = {0};
    if (!QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            &accounting,
            sizeof(accounting),
            NULL)) {
        return 0;
    }
    return accounting.ActiveProcesses;
}

static int parse_pid_file(const wchar_t *path, DWORD *pid) {
    HANDLE handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        return 1;
    }
    char buffer[64] = {0};
    DWORD read = 0;
    BOOL ok = ReadFile(handle, buffer, sizeof(buffer) - 1, &read, NULL);
    CloseHandle(handle);
    if (!ok || read == 0) {
        return 2;
    }
    unsigned long value = 0;
    if (sscanf(buffer, "%lu", &value) != 1 || value == 0) {
        return 3;
    }
    *pid = (DWORD)value;
    return 0;
}

static int tree_grandchild(const wchar_t *marker) {
    if (write_text(marker, "tree-grandchild-observed\n") != 0) {
        return 30;
    }
    Sleep(200);
    return 0;
}

static int tree_child(const wchar_t *marker) {
    wchar_t self[MAX_PATH];
    if (self_path(self, MAX_PATH) != 0) {
        return 31;
    }
    PROCESS_INFORMATION process = {0};
    if (spawn_process(self, L"--tree-grandchild", marker, &process) != 0) {
        return 32;
    }
    DWORD exit_code = 0;
    BOOL completed = wait_success(process.hProcess, 10000, &exit_code);
    CloseHandle(process.hProcess);
    return completed && exists(marker) ? 0 : 33;
}

static int kill_grandchild(const wchar_t *pid_file) {
    char value[64];
    snprintf(value, sizeof(value), "%lu\n", (unsigned long)GetCurrentProcessId());
    if (write_text(pid_file, value) != 0) {
        return 40;
    }
    Sleep(60000);
    return 0;
}

static int kill_child(const wchar_t *pid_file) {
    wchar_t self[MAX_PATH];
    if (self_path(self, MAX_PATH) != 0) {
        return 41;
    }
    PROCESS_INFORMATION process = {0};
    if (spawn_process(self, L"--kill-grandchild", pid_file, &process) != 0) {
        return 42;
    }
    WaitForSingleObject(process.hProcess, 60000);
    CloseHandle(process.hProcess);
    return 0;
}

static int block_secondary(const wchar_t *marker) {
    return write_text(marker, "secondary-executed\n") == 0 ? 0 : 50;
}

static int block_child(const wchar_t *marker) {
    wchar_t self[MAX_PATH];
    if (self_path(self, MAX_PATH) != 0) {
        return 51;
    }
    PROCESS_INFORMATION process = {0};
    int spawned = spawn_process(self, L"--block-secondary", marker, &process);
    if (spawned == 0) {
        WaitForSingleObject(process.hProcess, 3000);
        CloseHandle(process.hProcess);
    }
    Sleep(300);
    return exists(marker) ? 52 : 0;
}

static int controller_canary(const wchar_t *result_path) {
    wchar_t self[MAX_PATH];
    wchar_t tree_marker[MAX_PATH * 2];
    wchar_t kill_pid_file[MAX_PATH * 2];
    wchar_t block_marker[MAX_PATH * 2];
    if (self_path(self, MAX_PATH) != 0 ||
        sibling_path(result_path, L".tree", tree_marker, sizeof(tree_marker) / sizeof(tree_marker[0])) != 0 ||
        sibling_path(result_path, L".killpid", kill_pid_file, sizeof(kill_pid_file) / sizeof(kill_pid_file[0])) != 0 ||
        sibling_path(result_path, L".blocked", block_marker, sizeof(block_marker) / sizeof(block_marker[0])) != 0) {
        return 60;
    }
    DeleteFileW(tree_marker);
    DeleteFileW(kill_pid_file);
    DeleteFileW(block_marker);

    BOOL tree_owned = FALSE;
    DWORD tree_total = 0;
    HANDLE tree_job = create_job(8);
    if (tree_job != NULL) {
        PROCESS_INFORMATION process = {0};
        if (spawn_suspended_in_job(tree_job, self, L"--tree-child", tree_marker, &process) == 0) {
            DWORD exit_code = 0;
            BOOL completed = wait_success(process.hProcess, 15000, &exit_code);
            tree_total = job_total_processes(tree_job);
            tree_owned = completed && exists(tree_marker) && tree_total >= 2;
            CloseHandle(process.hProcess);
        }
        CloseHandle(tree_job);
    }

    BOOL kill_root = FALSE;
    BOOL kill_descendant = FALSE;
    DWORD kill_active_before_close = 0;
    HANDLE kill_job = create_job(8);
    if (kill_job != NULL) {
        PROCESS_INFORMATION process = {0};
        if (spawn_suspended_in_job(kill_job, self, L"--kill-child", kill_pid_file, &process) == 0) {
            DWORD descendant_pid = 0;
            for (int attempt = 0; attempt < 40 && descendant_pid == 0; attempt++) {
                if (parse_pid_file(kill_pid_file, &descendant_pid) != 0) {
                    Sleep(100);
                }
            }
            HANDLE descendant = NULL;
            if (descendant_pid != 0) {
                descendant = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, descendant_pid);
            }
            kill_active_before_close = job_active_processes(kill_job);
            CloseHandle(kill_job);
            kill_job = NULL;
            kill_root = WaitForSingleObject(process.hProcess, 5000) == WAIT_OBJECT_0;
            if (descendant != NULL) {
                kill_descendant = WaitForSingleObject(descendant, 5000) == WAIT_OBJECT_0;
                CloseHandle(descendant);
            }
            CloseHandle(process.hProcess);
        }
        if (kill_job != NULL) {
            CloseHandle(kill_job);
        }
    }

    BOOL secondary_blocked = FALSE;
    DWORD block_total = 0;
    HANDLE block_job = create_job(1);
    if (block_job != NULL) {
        PROCESS_INFORMATION process = {0};
        if (spawn_suspended_in_job(block_job, self, L"--block-child", block_marker, &process) == 0) {
            DWORD exit_code = 0;
            BOOL completed = wait_success(process.hProcess, 10000, &exit_code);
            block_total = job_total_processes(block_job);
            secondary_blocked = completed && !exists(block_marker);
            CloseHandle(process.hProcess);
        }
        CloseHandle(block_job);
    }

    DeleteFileW(tree_marker);
    DeleteFileW(kill_pid_file);
    DeleteFileW(block_marker);

    BOOL completed = tree_owned && kill_root && kill_descendant && secondary_blocked;
    char result[1800];
    int length = snprintf(
        result,
        sizeof(result),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.p1-controller-canary-result\","
        "\"fixtureId\":\"ordivon-p1-controller-canary-v1\","
        "\"jobObjectTreeOwned\":%s,\"treeTotalProcesses\":%lu,"
        "\"killOnJobCloseRootTerminated\":%s,\"killOnJobCloseDescendantTerminated\":%s,"
        "\"killActiveProcessesBeforeClose\":%lu,"
        "\"activeProcessLimitBlockedSecondary\":%s,\"blockJobTotalProcesses\":%lu,"
        "\"blockingPolicy\":\"job-active-process-limit-1\","
        "\"selectiveSecondaryBlocking\":false,\"networkRequested\":false,\"completed\":%s}\n",
        tree_owned ? "true" : "false",
        (unsigned long)tree_total,
        kill_root ? "true" : "false",
        kill_descendant ? "true" : "false",
        (unsigned long)kill_active_before_close,
        secondary_blocked ? "true" : "false",
        (unsigned long)block_total,
        completed ? "true" : "false"
    );
    if (length < 0 || length >= (int)sizeof(result)) {
        return 61;
    }
    if (write_text(result_path, result) != 0) {
        return 62;
    }
    return completed ? 0 : 63;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && wcscmp(argv[1], L"--tree-grandchild") == 0) {
        return tree_grandchild(argv[2]);
    }
    if (argc == 3 && wcscmp(argv[1], L"--tree-child") == 0) {
        return tree_child(argv[2]);
    }
    if (argc == 3 && wcscmp(argv[1], L"--kill-grandchild") == 0) {
        return kill_grandchild(argv[2]);
    }
    if (argc == 3 && wcscmp(argv[1], L"--kill-child") == 0) {
        return kill_child(argv[2]);
    }
    if (argc == 3 && wcscmp(argv[1], L"--block-secondary") == 0) {
        return block_secondary(argv[2]);
    }
    if (argc == 3 && wcscmp(argv[1], L"--block-child") == 0) {
        return block_child(argv[2]);
    }
    if (argc == 3 && wcscmp(argv[1], L"--result") == 0) {
        return controller_canary(argv[2]);
    }
    return 64;
}
