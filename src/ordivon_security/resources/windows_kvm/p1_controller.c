#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#define SELFTEST_MANIFEST_TEXT "ordivon-p1-controller-selftest-v1\n"
#define SELFTEST_MANIFEST_SHA256 "52f63e10322eb5f6b6021a00973ca2d6769dc5510a2f537b8dc67dadfa65e56c"
#define ORCHESTRATOR_PATH L"C:\\ProgramData\\Ordivon\\p1-orchestrator.ps1"
#define POWERSHELL_PATH L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

static int write_bytes(const wchar_t *path, const void *data, DWORD length) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    BOOL ok;
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    ok = WriteFile(file, data, length, &written, NULL);
    if (ok) {
        ok = FlushFileBuffers(file);
    }
    CloseHandle(file);
    return ok && written == length;
}

static int file_exists(const wchar_t *path) {
    DWORD attrs = GetFileAttributesW(path);
    return attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY);
}

static int safe_path_arg(const wchar_t *value) {
    const wchar_t *p;
    if (value == NULL || *value == L'\0') {
        return 0;
    }
    for (p = value; *p; ++p) {
        if (*p == L'"' || *p == L'\r' || *p == L'\n') {
            return 0;
        }
    }
    return 1;
}

static int safe_token(const wchar_t *value) {
    const wchar_t *p;
    if (value == NULL || *value == L'\0' || wcslen(value) > 160) {
        return 0;
    }
    for (p = value; *p; ++p) {
        wchar_t c = *p;
        if (!((c >= L'a' && c <= L'z') || (c >= L'A' && c <= L'Z') ||
              (c >= L'0' && c <= L'9') || c == L':' || c == L'.' ||
              c == L'_' || c == L'-')) {
            return 0;
        }
    }
    return 1;
}

static int parse_timeout(const wchar_t *value, DWORD *result) {
    wchar_t *end = NULL;
    unsigned long parsed;
    if (value == NULL || *value == L'\0') {
        return 0;
    }
    parsed = wcstoul(value, &end, 10);
    if (end == value || *end != L'\0' || parsed < 100 || parsed > 3600000UL) {
        return 0;
    }
    *result = (DWORD)parsed;
    return 1;
}

static int normalize_digest(const wchar_t *value, char output[65]) {
    const wchar_t *p = value;
    size_t i;
    if (p == NULL) {
        return 0;
    }
    if (_wcsnicmp(p, L"sha256:", 7) == 0) {
        p += 7;
    }
    if (wcslen(p) != 64) {
        return 0;
    }
    for (i = 0; i < 64; ++i) {
        wchar_t c = p[i];
        if (c >= L'0' && c <= L'9') {
            output[i] = (char)c;
        } else if (c >= L'a' && c <= L'f') {
            output[i] = (char)c;
        } else if (c >= L'A' && c <= L'F') {
            output[i] = (char)(c - L'A' + 'a');
        } else {
            return 0;
        }
    }
    output[64] = '\0';
    return 1;
}

static int sha256_file(const wchar_t *path, char output[65]) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR object = NULL;
    DWORD object_length = 0;
    DWORD result_length = 0;
    DWORD hash_length = 0;
    NTSTATUS status;
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE buffer[65536];
    DWORD read = 0;
    BYTE digest[32];
    static const char hex[] = "0123456789abcdef";
    int success = 0;
    size_t i;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0) goto cleanup;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_length,
                               sizeof(object_length), &result_length, 0);
    if (status < 0) goto cleanup;
    status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_length,
                               sizeof(hash_length), &result_length, 0);
    if (status < 0 || hash_length != sizeof(digest)) goto cleanup;
    object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, object_length);
    if (object == NULL) goto cleanup;
    status = BCryptCreateHash(algorithm, &hash, object, object_length, NULL, 0, 0);
    if (status < 0) goto cleanup;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) goto cleanup;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &read, NULL)) goto cleanup;
        if (read == 0) break;
        status = BCryptHashData(hash, buffer, read, 0);
        if (status < 0) goto cleanup;
    }
    status = BCryptFinishHash(hash, digest, sizeof(digest), 0);
    if (status < 0) goto cleanup;
    for (i = 0; i < sizeof(digest); ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    output[64] = '\0';
    success = 1;

cleanup:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (hash != NULL) BCryptDestroyHash(hash);
    if (object != NULL) HeapFree(GetProcessHeap(), 0, object);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    return success;
}

static HANDLE create_owned_job(void) {
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits;
    HANDLE job = CreateJobObjectW(NULL, NULL);
    if (job == NULL) return NULL;
    ZeroMemory(&limits, sizeof(limits));
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits))) {
        CloseHandle(job);
        return NULL;
    }
    return job;
}

static int launch_suspended_in_job(HANDLE job, wchar_t *command_line,
                                   PROCESS_INFORMATION *process_info) {
    STARTUPINFOW startup;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(process_info, sizeof(*process_info));
    if (!CreateProcessW(NULL, command_line, NULL, NULL, FALSE,
                        CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL,
                        &startup, process_info)) {
        return 0;
    }
    if (!AssignProcessToJobObject(job, process_info->hProcess)) {
        TerminateProcess(process_info->hProcess, 91);
        CloseHandle(process_info->hThread);
        CloseHandle(process_info->hProcess);
        ZeroMemory(process_info, sizeof(*process_info));
        return 0;
    }
    if (ResumeThread(process_info->hThread) == (DWORD)-1) {
        TerminateProcess(process_info->hProcess, 92);
        CloseHandle(process_info->hThread);
        CloseHandle(process_info->hProcess);
        ZeroMemory(process_info, sizeof(*process_info));
        return 0;
    }
    CloseHandle(process_info->hThread);
    process_info->hThread = NULL;
    return 1;
}

static int self_test_child(int argc, wchar_t **argv) {
    const wchar_t *marker = NULL;
    DWORD sleep_ms = 0;
    int i;
    for (i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--marker") == 0 && i + 1 < argc) {
            marker = argv[++i];
        } else if (wcscmp(argv[i], L"--sleep-ms") == 0 && i + 1 < argc) {
            if (!parse_timeout(argv[++i], &sleep_ms)) return 41;
        }
    }
    if (!safe_path_arg(marker)) return 42;
    if (sleep_ms > 0) Sleep(sleep_ms);
    if (!write_bytes(marker, "ok\n", 3)) return 43;
    return 0;
}

static int self_test(const wchar_t *result_path) {
    wchar_t self_path[32768];
    wchar_t marker_path[32768];
    wchar_t timeout_marker_path[32768];
    wchar_t manifest_path[32768];
    wchar_t command_line[32768];
    PROCESS_INFORMATION normal_child;
    PROCESS_INFORMATION timeout_child;
    HANDLE job = NULL;
    DWORD normal_wait;
    DWORD timeout_wait;
    DWORD normal_exit = STILL_ACTIVE;
    DWORD timeout_exit = STILL_ACTIVE;
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting;
    char manifest_digest[65];
    int manifest_digest_ok = 0;
    int normal_completed = 0;
    int normal_marker = 0;
    int timeout_observed = 0;
    int timeout_terminated = 0;
    int timeout_marker_absent = 0;
    int total_processes_ok = 0;
    char json[2048];
    int json_len;

    if (!safe_path_arg(result_path)) return 50;
    if (GetModuleFileNameW(NULL, self_path, ARRAYSIZE(self_path)) == 0) return 51;
    if (swprintf(marker_path, ARRAYSIZE(marker_path), L"%ls.selftest.marker", result_path) < 0 ||
        swprintf(timeout_marker_path, ARRAYSIZE(timeout_marker_path), L"%ls.timeout.marker", result_path) < 0 ||
        swprintf(manifest_path, ARRAYSIZE(manifest_path), L"%ls.selftest.manifest", result_path) < 0) {
        return 52;
    }
    DeleteFileW(marker_path);
    DeleteFileW(timeout_marker_path);
    DeleteFileW(manifest_path);
    if (!write_bytes(manifest_path, SELFTEST_MANIFEST_TEXT,
                     (DWORD)(sizeof(SELFTEST_MANIFEST_TEXT) - 1))) return 53;
    if (sha256_file(manifest_path, manifest_digest) &&
        strcmp(manifest_digest, SELFTEST_MANIFEST_SHA256) == 0) {
        manifest_digest_ok = 1;
    }

    job = create_owned_job();
    if (job == NULL) return 54;
    if (swprintf(command_line, ARRAYSIZE(command_line),
                 L"\"%ls\" --self-test-child --marker \"%ls\" --sleep-ms 100",
                 self_path, marker_path) < 0) goto cleanup;
    if (!launch_suspended_in_job(job, command_line, &normal_child)) goto cleanup;
    normal_wait = WaitForSingleObject(normal_child.hProcess, 10000);
    if (normal_wait == WAIT_OBJECT_0 && GetExitCodeProcess(normal_child.hProcess, &normal_exit) &&
        normal_exit == 0) {
        normal_completed = 1;
    }
    CloseHandle(normal_child.hProcess);
    normal_marker = file_exists(marker_path);

    if (swprintf(command_line, ARRAYSIZE(command_line),
                 L"\"%ls\" --self-test-child --marker \"%ls\" --sleep-ms 60000",
                 self_path, timeout_marker_path) < 0) goto cleanup;
    if (!launch_suspended_in_job(job, command_line, &timeout_child)) goto cleanup;
    timeout_wait = WaitForSingleObject(timeout_child.hProcess, 500);
    if (timeout_wait == WAIT_TIMEOUT) {
        timeout_observed = 1;
        if (TerminateJobObject(job, 93) &&
            WaitForSingleObject(timeout_child.hProcess, 10000) == WAIT_OBJECT_0 &&
            GetExitCodeProcess(timeout_child.hProcess, &timeout_exit) &&
            timeout_exit != STILL_ACTIVE) {
            timeout_terminated = 1;
        }
    }
    CloseHandle(timeout_child.hProcess);
    timeout_marker_absent = !file_exists(timeout_marker_path);
    ZeroMemory(&accounting, sizeof(accounting));
    if (QueryInformationJobObject(job, JobObjectBasicAccountingInformation,
                                  &accounting, sizeof(accounting), NULL) &&
        accounting.TotalProcesses >= 2) {
        total_processes_ok = 1;
    }

cleanup:
    if (job != NULL) CloseHandle(job);
    DeleteFileW(marker_path);
    DeleteFileW(timeout_marker_path);
    DeleteFileW(manifest_path);
    json_len = snprintf(
        json, sizeof(json),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.p1-controller-self-test-result\","
        "\"fixtureId\":\"ordivon-p1-generic-controller-selftest-v1\","
        "\"manifestDigestVerified\":%s,\"normalChildCompleted\":%s,"
        "\"normalMarkerObserved\":%s,\"timeoutObserved\":%s,"
        "\"timeoutChildTerminated\":%s,\"timeoutMarkerAbsent\":%s,"
        "\"jobTotalProcessesObserved\":%s,\"networkRequested\":false,"
        "\"completed\":%s}\n",
        manifest_digest_ok ? "true" : "false",
        normal_completed ? "true" : "false",
        normal_marker ? "true" : "false",
        timeout_observed ? "true" : "false",
        timeout_terminated ? "true" : "false",
        timeout_marker_absent ? "true" : "false",
        total_processes_ok ? "true" : "false",
        (manifest_digest_ok && normal_completed && normal_marker && timeout_observed &&
         timeout_terminated && timeout_marker_absent && total_processes_ok) ? "true" : "false"
    );
    if (json_len <= 0 || (size_t)json_len >= sizeof(json) ||
        !write_bytes(result_path, json, (DWORD)json_len)) {
        return 55;
    }
    return (manifest_digest_ok && normal_completed && normal_marker && timeout_observed &&
            timeout_terminated && timeout_marker_absent && total_processes_ok) ? 0 : 56;
}

static int production_controller(const wchar_t *run_id, const wchar_t *manifest_path,
                                 const wchar_t *manifest_digest_arg,
                                 const wchar_t *result_path, DWORD timeout_ms) {
    char expected_digest[65];
    char actual_digest[65];
    wchar_t orchestrator_result[32768];
    wchar_t command_line[32768];
    PROCESS_INFORMATION process_info;
    HANDLE job = NULL;
    DWORD wait_result;
    DWORD exit_code = STILL_ACTIVE;
    int timed_out = 0;
    int digest_verified = 0;
    char run_id_ascii[161];
    char json[2048];
    int json_len;
    size_t i;

    if (!safe_token(run_id) || !safe_path_arg(manifest_path) ||
        !safe_path_arg(result_path) || !normalize_digest(manifest_digest_arg, expected_digest)) {
        return 60;
    }
    if (!sha256_file(manifest_path, actual_digest) ||
        strcmp(actual_digest, expected_digest) != 0) {
        return 61;
    }
    digest_verified = 1;
    if (!file_exists(POWERSHELL_PATH) || !file_exists(ORCHESTRATOR_PATH)) return 62;
    if (swprintf(orchestrator_result, ARRAYSIZE(orchestrator_result),
                 L"%ls.orchestrator.json", result_path) < 0) return 63;
    if (swprintf(
            command_line, ARRAYSIZE(command_line),
            L"\"%ls\" -NoLogo -NoProfile -NonInteractive -File \"%ls\" "
            L"-Manifest \"%ls\" -Result \"%ls\" -RunId \"%ls\" "
            L"-BindingDigest \"sha256:%S\"",
            POWERSHELL_PATH, ORCHESTRATOR_PATH, manifest_path, orchestrator_result,
            run_id, actual_digest) < 0) {
        return 64;
    }
    job = create_owned_job();
    if (job == NULL) return 65;
    if (!launch_suspended_in_job(job, command_line, &process_info)) {
        CloseHandle(job);
        return 66;
    }
    wait_result = WaitForSingleObject(process_info.hProcess, timeout_ms);
    if (wait_result == WAIT_TIMEOUT) {
        timed_out = 1;
        TerminateJobObject(job, 94);
        WaitForSingleObject(process_info.hProcess, 10000);
    }
    GetExitCodeProcess(process_info.hProcess, &exit_code);
    CloseHandle(process_info.hProcess);
    CloseHandle(job);
    for (i = 0; run_id[i] && i < sizeof(run_id_ascii) - 1; ++i) {
        run_id_ascii[i] = (char)run_id[i];
    }
    run_id_ascii[i] = '\0';
    json_len = snprintf(
        json, sizeof(json),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.p1-controller-result\","
        "\"runId\":\"%s\",\"manifestDigest\":\"sha256:%s\","
        "\"manifestDigestVerified\":%s,\"timedOut\":%s,"
        "\"orchestratorExitCode\":%lu,\"networkRequested\":false,"
        "\"completed\":%s}\n",
        run_id_ascii, actual_digest, digest_verified ? "true" : "false",
        timed_out ? "true" : "false", (unsigned long)exit_code,
        (!timed_out && exit_code != STILL_ACTIVE) ? "true" : "false"
    );
    if (json_len <= 0 || (size_t)json_len >= sizeof(json) ||
        !write_bytes(result_path, json, (DWORD)json_len)) return 67;
    if (timed_out) return 68;
    return exit_code == 0 ? 0 : 69;
}

int wmain(int argc, wchar_t **argv) {
    const wchar_t *result_path = NULL;
    const wchar_t *run_id = NULL;
    const wchar_t *manifest_path = NULL;
    const wchar_t *manifest_digest = NULL;
    DWORD timeout_ms = 0;
    int self_test_mode = 0;
    int child_mode = 0;
    int i;

    for (i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--self-test") == 0) {
            self_test_mode = 1;
        } else if (wcscmp(argv[i], L"--self-test-child") == 0) {
            child_mode = 1;
        } else if (wcscmp(argv[i], L"--result") == 0 && i + 1 < argc) {
            result_path = argv[++i];
        } else if (wcscmp(argv[i], L"--run-id") == 0 && i + 1 < argc) {
            run_id = argv[++i];
        } else if (wcscmp(argv[i], L"--manifest") == 0 && i + 1 < argc) {
            manifest_path = argv[++i];
        } else if (wcscmp(argv[i], L"--manifest-digest") == 0 && i + 1 < argc) {
            manifest_digest = argv[++i];
        } else if (wcscmp(argv[i], L"--timeout-ms") == 0 && i + 1 < argc) {
            if (!parse_timeout(argv[++i], &timeout_ms)) return 2;
        }
    }
    if (child_mode) return self_test_child(argc, argv);
    if (self_test_mode ||
        (result_path != NULL && run_id == NULL && manifest_path == NULL &&
         manifest_digest == NULL && timeout_ms == 0)) {
        if (result_path == NULL) return 3;
        return self_test(result_path);
    }
    if (result_path == NULL || run_id == NULL || manifest_path == NULL ||
        manifest_digest == NULL || timeout_ms == 0) {
        return 4;
    }
    return production_controller(run_id, manifest_path, manifest_digest, result_path, timeout_ms);
}
