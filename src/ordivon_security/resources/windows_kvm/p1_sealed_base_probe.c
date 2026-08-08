#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CONTROLLER_PATH L"C:\\ProgramData\\Ordivon\\p1-controller.exe"
#define CONTROL_PATH L"C:\\ProgramData\\Ordivon\\acceptance\\p1-execution-control-canary.exe"
#define CONTROLLER_SHA256 "eb7e9874f1dc568721c826ea30e1b77f325254244564ca70381d2556f3d4388a"
#define CONTROL_SHA256 "d29becd1409bab42bbba885b3e6db5623cedaf61d83d6c3b01ed7111e347d655"
#define CONTROLLER_BYTES 25600ULL
#define CONTROL_BYTES 27648ULL

static int safe_path_arg(const wchar_t *value) {
    const wchar_t *p;
    if (value == NULL || *value == L'\0') return 0;
    for (p = value; *p; ++p) {
        if (*p == L'"' || *p == L'\r' || *p == L'\n') return 0;
    }
    return 1;
}

static int write_bytes(const wchar_t *path, const void *data, DWORD length) {
    HANDLE file = CreateFileW(
        path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    );
    DWORD written = 0;
    BOOL ok;
    if (file == INVALID_HANDLE_VALUE) return 0;
    ok = WriteFile(file, data, length, &written, NULL);
    if (ok) ok = FlushFileBuffers(file);
    CloseHandle(file);
    return ok && written == length;
}

static int sha256_file(const wchar_t *path, char output[65], uint64_t *byte_length) {
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
    uint64_t total = 0;
    int success = 0;
    size_t i;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0) goto cleanup;
    status = BCryptGetProperty(
        algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_length,
        sizeof(object_length), &result_length, 0
    );
    if (status < 0) goto cleanup;
    status = BCryptGetProperty(
        algorithm, BCRYPT_HASH_LENGTH, (PUCHAR)&hash_length,
        sizeof(hash_length), &result_length, 0
    );
    if (status < 0 || hash_length != sizeof(digest)) goto cleanup;
    object = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, object_length);
    if (object == NULL) goto cleanup;
    status = BCryptCreateHash(algorithm, &hash, object, object_length, NULL, 0, 0);
    if (status < 0) goto cleanup;
    file = CreateFileW(
        path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL
    );
    if (file == INVALID_HANDLE_VALUE) goto cleanup;
    for (;;) {
        if (!ReadFile(file, buffer, sizeof(buffer), &read, NULL)) goto cleanup;
        if (read == 0) break;
        total += read;
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
    if (byte_length != NULL) *byte_length = total;
    success = 1;

cleanup:
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    if (hash != NULL) BCryptDestroyHash(hash);
    if (object != NULL) HeapFree(GetProcessHeap(), 0, object);
    if (algorithm != NULL) BCryptCloseAlgorithmProvider(algorithm, 0);
    return success;
}

static int file_contains(const wchar_t *path, const char *needle) {
    HANDLE file;
    LARGE_INTEGER size;
    char *buffer = NULL;
    DWORD read = 0;
    int found = 0;
    if (needle == NULL || *needle == '\0') return 0;
    file = CreateFileW(
        path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (file == INVALID_HANDLE_VALUE) return 0;
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 1 || size.QuadPart > 65536) {
        CloseHandle(file);
        return 0;
    }
    buffer = (char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)size.QuadPart + 1);
    if (buffer == NULL) {
        CloseHandle(file);
        return 0;
    }
    if (ReadFile(file, buffer, (DWORD)size.QuadPart, &read, NULL) &&
        read == (DWORD)size.QuadPart && strstr(buffer, needle) != NULL) {
        found = 1;
    }
    HeapFree(GetProcessHeap(), 0, buffer);
    CloseHandle(file);
    return found;
}

static int run_child(
    const wchar_t *application,
    const wchar_t *arguments,
    DWORD timeout_ms,
    DWORD *exit_code
) {
    wchar_t command[32768];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD wait_result;
    DWORD code = STILL_ACTIVE;
    int length;

    length = swprintf(command, ARRAYSIZE(command), L"\"%ls\" %ls", application, arguments);
    if (length < 0 || (size_t)length >= ARRAYSIZE(command)) return 0;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));
    if (!CreateProcessW(
            application, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
            NULL, NULL, &startup, &process)) {
        return 0;
    }
    CloseHandle(process.hThread);
    wait_result = WaitForSingleObject(process.hProcess, timeout_ms);
    if (wait_result != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 90);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hProcess);
        return 0;
    }
    if (!GetExitCodeProcess(process.hProcess, &code)) {
        CloseHandle(process.hProcess);
        return 0;
    }
    CloseHandle(process.hProcess);
    if (exit_code != NULL) *exit_code = code;
    return 1;
}

static int sealed_base_probe(const wchar_t *result_path) {
    wchar_t controller_result[32768];
    wchar_t control_result[32768];
    wchar_t arguments[32768];
    char controller_digest[65];
    char control_digest[65];
    uint64_t controller_bytes = 0;
    uint64_t control_bytes = 0;
    DWORD controller_exit = STILL_ACTIVE;
    DWORD control_exit = STILL_ACTIVE;
    int controller_identity_ok = 0;
    int control_identity_ok = 0;
    int controller_started = 0;
    int control_started = 0;
    int controller_semantics_ok = 0;
    int control_semantics_ok = 0;
    int completed = 0;
    char json[3072];
    int json_len;

    if (!safe_path_arg(result_path)) return 20;
    if (swprintf(
            controller_result, ARRAYSIZE(controller_result),
            L"%ls.controller.json", result_path) < 0 ||
        swprintf(
            control_result, ARRAYSIZE(control_result),
            L"%ls.execution-control.json", result_path) < 0) {
        return 21;
    }
    DeleteFileW(controller_result);
    DeleteFileW(control_result);

    if (sha256_file(CONTROLLER_PATH, controller_digest, &controller_bytes) &&
        strcmp(controller_digest, CONTROLLER_SHA256) == 0 &&
        controller_bytes == CONTROLLER_BYTES) {
        controller_identity_ok = 1;
    }
    if (sha256_file(CONTROL_PATH, control_digest, &control_bytes) &&
        strcmp(control_digest, CONTROL_SHA256) == 0 &&
        control_bytes == CONTROL_BYTES) {
        control_identity_ok = 1;
    }

    if (controller_identity_ok) {
        if (swprintf(
                arguments, ARRAYSIZE(arguments),
                L"--self-test --result \"%ls\"", controller_result) >= 0) {
            controller_started = run_child(
                CONTROLLER_PATH, arguments, 30000, &controller_exit
            );
        }
        controller_semantics_ok =
            controller_started && controller_exit == 0 &&
            file_contains(controller_result, "\"completed\":true") &&
            file_contains(controller_result, "\"manifestDigestVerified\":true") &&
            file_contains(controller_result, "\"timeoutChildTerminated\":true") &&
            file_contains(controller_result, "\"timeoutMarkerAbsent\":true");
    }

    if (control_identity_ok) {
        if (swprintf(
                arguments, ARRAYSIZE(arguments),
                L"--result \"%ls\"", control_result) >= 0) {
            control_started = run_child(CONTROL_PATH, arguments, 90000, &control_exit);
        }
        control_semantics_ok =
            control_started && control_exit == 0 &&
            file_contains(control_result, "\"completed\":true") &&
            file_contains(control_result, "\"selectiveExecutionControl\":true") &&
            file_contains(control_result, "\"blockedChildStartDenied\":true") &&
            file_contains(control_result, "\"nestedBlockedChildStartDenied\":true") &&
            file_contains(control_result, "\"rootWriteProbeSucceeded\":true") &&
            file_contains(control_result, "\"nestedWriteProbeSucceeded\":true");
    }

    completed = controller_identity_ok && control_identity_ok &&
                controller_semantics_ok && control_semantics_ok;
    json_len = snprintf(
        json, sizeof(json),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.p1-sealed-base-probe-result\","
        "\"fixtureId\":\"ordivon-p1-sealed-base-probe-v1\","
        "\"controllerPath\":\"C:\\\\ProgramData\\\\Ordivon\\\\p1-controller.exe\","
        "\"controllerDigest\":\"sha256:%s\",\"controllerByteLength\":%llu,"
        "\"controllerIdentityVerified\":%s,\"controllerExitCode\":%lu,"
        "\"controllerSelfTestVerified\":%s,"
        "\"executionControlPath\":\"C:\\\\ProgramData\\\\Ordivon\\\\acceptance\\\\p1-execution-control-canary.exe\","
        "\"executionControlDigest\":\"sha256:%s\",\"executionControlByteLength\":%llu,"
        "\"executionControlIdentityVerified\":%s,\"executionControlExitCode\":%lu,"
        "\"executionControlSelfTestVerified\":%s,"
        "\"networkRequested\":false,\"thirdPartySampleExecuted\":false,"
        "\"completed\":%s}\n",
        controller_identity_ok ? controller_digest : "",
        (unsigned long long)controller_bytes,
        controller_identity_ok ? "true" : "false",
        (unsigned long)controller_exit,
        controller_semantics_ok ? "true" : "false",
        control_identity_ok ? control_digest : "",
        (unsigned long long)control_bytes,
        control_identity_ok ? "true" : "false",
        (unsigned long)control_exit,
        control_semantics_ok ? "true" : "false",
        completed ? "true" : "false"
    );
    if (json_len <= 0 || (size_t)json_len >= sizeof(json) ||
        !write_bytes(result_path, json, (DWORD)json_len)) {
        return 22;
    }
    DeleteFileW(controller_result);
    DeleteFileW(control_result);
    return completed ? 0 : 23;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && wcscmp(argv[1], L"--result") == 0) {
        return sealed_base_probe(argv[2]);
    }
    return 64;
}
