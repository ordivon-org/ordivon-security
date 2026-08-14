#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <winevt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "ca1_embedded_assets.h"

#ifndef CA1_CARRIER
#error CA1_CARRIER must be defined
#endif

#define WORK_ROOT L"C:\\ProgramData\\Ordivon\\ca1"
#define EFFECT_PATH L"C:\\ProgramData\\Ordivon\\ca1\\effect.exe"
#define MARKER_PATH L"C:\\ProgramData\\Ordivon\\ca1\\effect.marker"
#define EFFECT_EVIDENCE_PATH L"C:\\ProgramData\\Ordivon\\ca1\\effect-evidence.json"
#define PS_PATH L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
#define PS_SCRIPT_PATH L"C:\\ProgramData\\Ordivon\\ca1\\carrier.ps1"
#define WSH_PATH L"C:\\Windows\\System32\\cscript.exe"
#define WSH_SCRIPT_PATH L"C:\\ProgramData\\Ordivon\\ca1\\carrier.vbs"
#define MSIEXEC_PATH L"C:\\Windows\\System32\\msiexec.exe"
#define MSI_PATH L"C:\\ProgramData\\Ordivon\\ca1\\carrier.msi"
#define MSI_LOG_PATH L"C:\\ProgramData\\Ordivon\\ca1\\carrier-msi.log"
#define MSI_INSTALLED_EFFECT L"C:\\Program Files\\OrdivonCA1\\effect.exe"
#define OFFICE_WORD_X64 L"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
#define OFFICE_WORD_X86 L"C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
#define PRODUCT_CODE_W L"{D1C2146B-8AD8-4C5E-B782-F414717A1011}"

static const char EFFECT_BYTES[] = "ordivon-ca1-same-effect-v1\n";
static const char PS_SCRIPT[] =
    "$ErrorActionPreference = 'Stop'\r\n"
    "& 'C:\\ProgramData\\Ordivon\\ca1\\effect.exe' "
    "'C:\\ProgramData\\Ordivon\\ca1\\effect.marker' "
    "'C:\\ProgramData\\Ordivon\\ca1\\effect-evidence.json'\r\n"
    "exit $LASTEXITCODE\r\n";
static const char VBS_SCRIPT[] =
    "Set sh = CreateObject(\"WScript.Shell\")\r\n"
    "rc = sh.Run(\"\"\"C:\\ProgramData\\Ordivon\\ca1\\effect.exe\"\" "
    "\"\"C:\\ProgramData\\Ordivon\\ca1\\effect.marker\"\" "
    "\"\"C:\\ProgramData\\Ordivon\\ca1\\effect-evidence.json\"\"\", 0, True)\r\n"
    "WScript.Quit rc\r\n";

static int safe_path_arg(const wchar_t *value) {
    const wchar_t *p;
    if (value == NULL || *value == L'\0') return 0;
    for (p = value; *p; ++p) {
        if (*p == L'\"' || *p == L'\r' || *p == L'\n') return 0;
    }
    return 1;
}

static int file_exists(const wchar_t *path) {
    DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static int write_bytes(const wchar_t *path, const void *data, DWORD length) {
    HANDLE file;
    DWORD written = 0;
    BOOL ok;
    file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    ok = WriteFile(file, data, length, &written, NULL);
    if (ok) ok = FlushFileBuffers(file);
    CloseHandle(file);
    return ok && written == length;
}

static int file_exact_bytes(const wchar_t *path, const void *expected, DWORD expected_length) {
    HANDLE file;
    LARGE_INTEGER size;
    BYTE *buffer = NULL;
    DWORD read = 0;
    int ok = 0;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    if (!GetFileSizeEx(file, &size) || size.QuadPart != expected_length) goto done;
    buffer = (BYTE *)HeapAlloc(GetProcessHeap(), 0, expected_length == 0 ? 1 : expected_length);
    if (buffer == NULL) goto done;
    if (!ReadFile(file, buffer, expected_length, &read, NULL) || read != expected_length) goto done;
    ok = memcmp(buffer, expected, expected_length) == 0;
done:
    if (buffer != NULL) HeapFree(GetProcessHeap(), 0, buffer);
    CloseHandle(file);
    return ok;
}

static long count_event_log(const wchar_t *channel, const wchar_t *query) {
    EVT_HANDLE result = NULL;
    EVT_HANDLE events[32];
    DWORD returned = 0;
    DWORD error = ERROR_SUCCESS;
    long total = 0;
    DWORD i;
    result = EvtQuery(NULL, channel, query, EvtQueryChannelPath);
    if (result == NULL) return -1;
    for (;;) {
        returned = 0;
        if (!EvtNext(result, ARRAYSIZE(events), events, 0, 0, &returned)) {
            error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) break;
            EvtClose(result);
            return -1;
        }
        for (i = 0; i < returned; ++i) {
            EvtClose(events[i]);
            total += 1;
            if (total >= 8192) {
                EvtClose(result);
                return total;
            }
        }
    }
    EvtClose(result);
    return total;
}

static int file_contains(const wchar_t *path, const char *needle) {
    HANDLE file;
    LARGE_INTEGER size;
    char *buffer = NULL;
    DWORD read = 0;
    int found = 0;
    if (needle == NULL || *needle == '\0') return 0;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 1 || size.QuadPart > 1024 * 1024) goto done;
    buffer = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)size.QuadPart + 1);
    if (buffer == NULL) goto done;
    if (ReadFile(file, buffer, (DWORD)size.QuadPart, &read, NULL) &&
        read == (DWORD)size.QuadPart && strstr(buffer, needle) != NULL) {
        found = 1;
    }
done:
    if (buffer != NULL) HeapFree(GetProcessHeap(), 0, buffer);
    CloseHandle(file);
    return found;
}

static int sha256_file(const wchar_t *path, char output[65], uint64_t *byte_length) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    PUCHAR object = NULL;
    DWORD object_length = 0, result_length = 0, hash_length = 0, read = 0;
    NTSTATUS status;
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE buffer[65536], digest[32];
    uint64_t total = 0;
    static const char hex[] = "0123456789abcdef";
    size_t i;
    int success = 0;
    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0) goto done;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_length,
                               sizeof(object_length), &result_length, 0);
    if (status < 0) goto done;
    status = BCryptGetProperty(algorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_length,
                               sizeof(hash_length), &result_length, 0);
    if (status < 0 || hash_length != sizeof(digest)) goto done;
    object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, object_length);
    if (object == NULL) goto done;
    status = BCryptCreateHash(algorithm, &hash, object, object_length, NULL, 0, 0);
    if (status < 0) goto done;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) goto done;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &read, NULL)) goto done;
        if (read == 0) break;
        total += read;
        if (BCryptHashData(hash, buffer, read, 0) < 0) goto done;
    }
    if (BCryptFinishHash(hash, digest, sizeof(digest), 0) < 0) goto done;
    for (i = 0; i < sizeof(digest); ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    output[64] = '\0';
    if (byte_length != NULL) *byte_length = total;
    success = 1;
done:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (hash != NULL) BCryptDestroyHash(hash);
    if (object != NULL) HeapFree(GetProcessHeap(), 0, object);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    return success;
}

static int ensure_work_root(void) {
    DWORD attrs = GetFileAttributesW(WORK_ROOT);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) return 1;
    if (CreateDirectoryW(WORK_ROOT, NULL)) return 1;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

static int run_process(
    const wchar_t *application, wchar_t *command_line, DWORD timeout_ms,
    DWORD *exit_code, uint64_t *elapsed_ms
) {
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD wait_result;
    DWORD code = STILL_ACTIVE;
    ULONGLONG started = GetTickCount64();
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));
    if (!CreateProcessW(application, command_line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup, &process)) return 0;
    CloseHandle(process.hThread);
    wait_result = WaitForSingleObject(process.hProcess, timeout_ms);
    if (wait_result != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 94);
        WaitForSingleObject(process.hProcess, 10000);
        CloseHandle(process.hProcess);
        if (elapsed_ms != NULL) *elapsed_ms = GetTickCount64() - started;
        return 0;
    }
    if (!GetExitCodeProcess(process.hProcess, &code)) {
        CloseHandle(process.hProcess);
        return 0;
    }
    CloseHandle(process.hProcess);
    if (exit_code != NULL) *exit_code = code;
    if (elapsed_ms != NULL) *elapsed_ms = GetTickCount64() - started;
    return 1;
}

static void cleanup_common(void) {
    DeleteFileW(MARKER_PATH);
    DeleteFileW(EFFECT_EVIDENCE_PATH);
    DeleteFileW(PS_SCRIPT_PATH);
    DeleteFileW(WSH_SCRIPT_PATH);
    DeleteFileW(MSI_LOG_PATH);
    DeleteFileW(MSI_PATH);
    DeleteFileW(EFFECT_PATH);
    RemoveDirectoryW(WORK_ROOT);
}

static int run_native(DWORD *exit_code, uint64_t *elapsed_ms) {
    wchar_t cmd[4096];
    if (swprintf(cmd, ARRAYSIZE(cmd), L"\"%ls\" \"%ls\" \"%ls\"",
                 EFFECT_PATH, MARKER_PATH, EFFECT_EVIDENCE_PATH) < 0) return 0;
    return run_process(EFFECT_PATH, cmd, 30000, exit_code, elapsed_ms);
}

static int run_powershell(DWORD *exit_code, uint64_t *elapsed_ms) {
    wchar_t cmd[4096];
    if (!write_bytes(PS_SCRIPT_PATH, PS_SCRIPT, (DWORD)(sizeof(PS_SCRIPT) - 1))) return 0;
    if (swprintf(cmd, ARRAYSIZE(cmd),
                 L"\"%ls\" -NoLogo -NoProfile -NonInteractive -File \"%ls\"",
                 PS_PATH, PS_SCRIPT_PATH) < 0) return 0;
    return run_process(PS_PATH, cmd, 30000, exit_code, elapsed_ms);
}

static int run_powershell_restricted_gate(DWORD *exit_code, int *marker_absent) {
    wchar_t cmd[4096];
    uint64_t ignored = 0;
    DeleteFileW(MARKER_PATH);
    DeleteFileW(EFFECT_EVIDENCE_PATH);
    if (swprintf(cmd, ARRAYSIZE(cmd),
                 L"\"%ls\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Restricted "
                 L"-File \"%ls\"", PS_PATH, PS_SCRIPT_PATH) < 0) return 0;
    if (!run_process(PS_PATH, cmd, 30000, exit_code, &ignored)) return 0;
    if (marker_absent != NULL) *marker_absent = !file_exists(MARKER_PATH);
    return 1;
}

static int run_wsh(DWORD *exit_code, uint64_t *elapsed_ms) {
    wchar_t cmd[4096];
    if (!write_bytes(WSH_SCRIPT_PATH, VBS_SCRIPT, (DWORD)(sizeof(VBS_SCRIPT) - 1))) return 0;
    if (swprintf(cmd, ARRAYSIZE(cmd), L"\"%ls\" //B //NoLogo \"%ls\"",
                 WSH_PATH, WSH_SCRIPT_PATH) < 0) return 0;
    return run_process(WSH_PATH, cmd, 30000, exit_code, elapsed_ms);
}

static int run_msi(DWORD *exit_code, uint64_t *elapsed_ms, DWORD *uninstall_exit) {
    wchar_t install_cmd[8192], uninstall_cmd[4096];
    uint64_t ignored = 0;
    if (!write_bytes(MSI_PATH, CA1_MSI_BYTES, (DWORD)CA1_MSI_BYTE_LENGTH)) return 0;
    if (swprintf(install_cmd, ARRAYSIZE(install_cmd),
                 L"\"%ls\" /i \"%ls\" /qn /norestart /l*v \"%ls\"",
                 MSIEXEC_PATH, MSI_PATH, MSI_LOG_PATH) < 0) return 0;
    if (!run_process(MSIEXEC_PATH, install_cmd, 90000, exit_code, elapsed_ms)) return 0;
    if (swprintf(uninstall_cmd, ARRAYSIZE(uninstall_cmd),
                 L"\"%ls\" /x %ls /qn /norestart", MSIEXEC_PATH, PRODUCT_CODE_W) < 0) return 0;
    if (!run_process(MSIEXEC_PATH, uninstall_cmd, 90000, uninstall_exit, &ignored)) return 0;
    return 1;
}

static const char *carrier_name(void) {
#if CA1_CARRIER == 0
    return "native";
#elif CA1_CARRIER == 1
    return "powershell";
#elif CA1_CARRIER == 2
    return "wsh-vbscript";
#elif CA1_CARRIER == 3
    return "msi-installed-custom-action";
#else
    return "invalid";
#endif
}

static int expected_parent_observed(void) {
#if CA1_CARRIER == 1
    return file_contains(EFFECT_EVIDENCE_PATH, "powershell.exe");
#elif CA1_CARRIER == 2
    return file_contains(EFFECT_EVIDENCE_PATH, "cscript.exe");
#elif CA1_CARRIER == 3
    return file_contains(EFFECT_EVIDENCE_PATH, "msiexec.exe");
#else
    return file_contains(EFFECT_EVIDENCE_PATH, "ca1-carrier-probe") ||
           file_contains(EFFECT_EVIDENCE_PATH, "sample");
#endif
}

static int carrier_probe(const wchar_t *result_path) {
    DWORD carrier_exit = STILL_ACTIVE;
    DWORD uninstall_exit = STILL_ACTIVE;
    DWORD restricted_exit = STILL_ACTIVE;
    uint64_t elapsed_ms = 0;
    uint64_t effect_bytes = 0, msi_bytes = 0;
    char effect_digest[65] = "", msi_digest[65] = "";
    int started = 0;
    int marker_exact = 0;
    int evidence_present = 0;
    int parent_match = 0;
    int system_sid = 0;
    int cleanup_complete = 0;
    int msi_log_present = 0;
    int installed_payload_removed = 1;
    int restricted_gate_started = 0;
    int restricted_marker_absent = 0;
    int restricted_blocked = 0;
    int powershell_present = file_exists(PS_PATH);
    int wsh_present = file_exists(WSH_PATH);
    int msiexec_present = file_exists(MSIEXEC_PATH);
    int office_present = file_exists(OFFICE_WORD_X64) || file_exists(OFFICE_WORD_X86);
    long powershell_events_before = -1, powershell_events_after = -1;
    long msi_events_before = -1, msi_events_after = -1;
    long powershell_event_delta = -1, msi_event_delta = -1;
    int completed = 0;
    char output[16384];
    int output_len;

    if (!safe_path_arg(result_path) || !ensure_work_root()) return 20;
    cleanup_common();
    if (!ensure_work_root()) return 21;
    if (!write_bytes(EFFECT_PATH, CA1_EFFECT_EXE_BYTES, (DWORD)CA1_EFFECT_EXE_BYTE_LENGTH)) return 22;
    if (!sha256_file(EFFECT_PATH, effect_digest, &effect_bytes) ||
        strcmp(effect_digest, CA1_EFFECT_EXE_SHA256) != 0 ||
        effect_bytes != CA1_EFFECT_EXE_BYTE_LENGTH) return 23;

    powershell_events_before = count_event_log(
        L"Microsoft-Windows-PowerShell/Operational", L"*"
    );
    msi_events_before = count_event_log(
        L"Application", L"*[System[Provider[@Name='MsiInstaller']]]"
    );

#if CA1_CARRIER == 0
    started = run_native(&carrier_exit, &elapsed_ms);
#elif CA1_CARRIER == 1
    started = powershell_present && run_powershell(&carrier_exit, &elapsed_ms);
#elif CA1_CARRIER == 2
    started = wsh_present && run_wsh(&carrier_exit, &elapsed_ms);
#elif CA1_CARRIER == 3
    if (!write_bytes(MSI_PATH, CA1_MSI_BYTES, (DWORD)CA1_MSI_BYTE_LENGTH)) return 24;
    if (!sha256_file(MSI_PATH, msi_digest, &msi_bytes) ||
        strcmp(msi_digest, CA1_MSI_SHA256) != 0 || msi_bytes != CA1_MSI_BYTE_LENGTH) return 25;
    DeleteFileW(MSI_PATH);
    started = msiexec_present && run_msi(&carrier_exit, &elapsed_ms, &uninstall_exit);
#else
    return 26;
#endif

    marker_exact = file_exact_bytes(MARKER_PATH, EFFECT_BYTES, (DWORD)(sizeof(EFFECT_BYTES) - 1));
    evidence_present = file_exists(EFFECT_EVIDENCE_PATH);
    parent_match = evidence_present && expected_parent_observed();
    system_sid = evidence_present && file_contains(EFFECT_EVIDENCE_PATH, "S-1-5-18");
#if CA1_CARRIER == 3
    msi_log_present = file_exists(MSI_LOG_PATH);
    installed_payload_removed = !file_exists(MSI_INSTALLED_EFFECT);
#endif

#if CA1_CARRIER == 1
    if (marker_exact && evidence_present) {
        restricted_gate_started = run_powershell_restricted_gate(
            &restricted_exit, &restricted_marker_absent
        );
        restricted_blocked = restricted_gate_started && restricted_exit != 0 && restricted_marker_absent;
        /* Restore the accepted semantic effect after the negative policy gate. */
        if (restricted_gate_started) {
            DWORD restore_exit = STILL_ACTIVE;
            uint64_t restore_elapsed = 0;
            if (!run_powershell(&restore_exit, &restore_elapsed) || restore_exit != 0) return 27;
            marker_exact = file_exact_bytes(
                MARKER_PATH, EFFECT_BYTES, (DWORD)(sizeof(EFFECT_BYTES) - 1)
            );
            evidence_present = file_exists(EFFECT_EVIDENCE_PATH);
            parent_match = evidence_present && expected_parent_observed();
            system_sid = evidence_present && file_contains(EFFECT_EVIDENCE_PATH, "S-1-5-18");
        }
    }
#endif

    powershell_events_after = count_event_log(
        L"Microsoft-Windows-PowerShell/Operational", L"*"
    );
    msi_events_after = count_event_log(
        L"Application", L"*[System[Provider[@Name='MsiInstaller']]]"
    );
    if (powershell_events_before >= 0 && powershell_events_after >= powershell_events_before)
        powershell_event_delta = powershell_events_after - powershell_events_before;
    if (msi_events_before >= 0 && msi_events_after >= msi_events_before)
        msi_event_delta = msi_events_after - msi_events_before;

    completed = started && carrier_exit == 0 && marker_exact && evidence_present && system_sid;
#if CA1_CARRIER == 3
    completed = completed && uninstall_exit == 0 && installed_payload_removed;
#endif

    /* Preserve semantic result in the returned evidence before deleting local experiment files. */
    output_len = snprintf(
        output, sizeof(output),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.ca1-carrier-probe-result\","
        "\"fixtureId\":\"ordivon-ca1-carrier-probe-v1:%s\","
        "\"carrier\":\"%s\",\"semanticEffectId\":\"ca1-same-effect-v1\","
        "\"carrierStarted\":%s,\"carrierExitCode\":%lu,\"carrierElapsedMs\":%llu,"
        "\"markerExact\":%s,\"effectEvidencePresent\":%s,"
        "\"effectRanAsSystem\":%s,\"expectedParentObserved\":%s,"
        "\"effectPayloadSha256\":\"sha256:%s\",\"effectPayloadByteLength\":%llu,"
        "\"powershellPresent\":%s,\"wshPresent\":%s,\"msiexecPresent\":%s,"
        "\"officeWordProviderPresent\":%s,"
        "\"blueTelemetry\":{"
        "\"powershellOperationalBefore\":%ld,\"powershellOperationalAfter\":%ld,"
        "\"powershellOperationalDelta\":%ld,"
        "\"msiInstallerApplicationBefore\":%ld,\"msiInstallerApplicationAfter\":%ld,"
        "\"msiInstallerApplicationDelta\":%ld},"
        "\"powershellRestrictedGateStarted\":%s,"
        "\"powershellRestrictedExitCode\":%lu,"
        "\"powershellRestrictedMarkerAbsent\":%s,"
        "\"powershellRestrictedBlocked\":%s,"
        "\"msiSha256\":\"%s%s\",\"msiByteLength\":%llu,"
        "\"msiLogPresent\":%s,\"msiUninstallExitCode\":%lu,"
        "\"msiInstalledPayloadRemoved\":%s,"
        "\"networkRequested\":false,\"thirdPartySampleExecuted\":false,"
        "\"completed\":%s}\n",
        carrier_name(), carrier_name(), started ? "true" : "false", (unsigned long)carrier_exit,
        (unsigned long long)elapsed_ms,
        marker_exact ? "true" : "false", evidence_present ? "true" : "false",
        system_sid ? "true" : "false", parent_match ? "true" : "false",
        effect_digest, (unsigned long long)effect_bytes,
        powershell_present ? "true" : "false", wsh_present ? "true" : "false",
        msiexec_present ? "true" : "false", office_present ? "true" : "false",
        powershell_events_before, powershell_events_after, powershell_event_delta,
        msi_events_before, msi_events_after, msi_event_delta,
        restricted_gate_started ? "true" : "false", (unsigned long)restricted_exit,
        restricted_marker_absent ? "true" : "false", restricted_blocked ? "true" : "false",
#if CA1_CARRIER == 3
        "sha256:", msi_digest, (unsigned long long)msi_bytes,
        msi_log_present ? "true" : "false", (unsigned long)uninstall_exit,
        installed_payload_removed ? "true" : "false",
#else
        "", "", 0ULL, "false", 0UL, "true",
#endif
        completed ? "true" : "false"
    );
    if (output_len <= 0 || (size_t)output_len >= sizeof(output)) return 28;

    cleanup_common();
    cleanup_complete = !file_exists(EFFECT_PATH) && !file_exists(MARKER_PATH) &&
                       !file_exists(EFFECT_EVIDENCE_PATH) && !file_exists(PS_SCRIPT_PATH) &&
                       !file_exists(WSH_SCRIPT_PATH) && !file_exists(MSI_PATH);
    if (!cleanup_complete) return 29;
    if (!write_bytes(result_path, output, (DWORD)output_len)) return 30;
    return completed ? 0 : 31;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && wcscmp(argv[1], L"--result") == 0) {
        return carrier_probe(argv[2]);
    }
    return 64;
}
