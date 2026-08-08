#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define CONTROLLER_PATH L"C:\\ProgramData\\Ordivon\\p1-controller.exe"
#define RUN_ID_W L"r6c-maintained-control-self-test"
#define RUN_ID_A "r6c-maintained-control-self-test"
#define CONTROL_DIGEST "sha256:d29becd1409bab42bbba885b3e6db5623cedaf61d83d6c3b01ed7111e347d655"

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

static int file_exists(const wchar_t *path) {
    DWORD attributes = GetFileAttributesW(path);
    return attributes != INVALID_FILE_ATTRIBUTES &&
           (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
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
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 1 || size.QuadPart > 262144) {
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

static int run_controller(
    const wchar_t *manifest_path,
    const char *manifest_digest,
    const wchar_t *controller_result,
    DWORD *exit_code
) {
    wchar_t command[32768];
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD waited;
    DWORD code = STILL_ACTIVE;
    int length;

    length = swprintf(
        command, ARRAYSIZE(command),
        L"\"%ls\" --run-id \"%ls\" --manifest \"%ls\" "
        L"--manifest-digest \"sha256:%S\" --result \"%ls\" --timeout-ms 60000",
        CONTROLLER_PATH, RUN_ID_W, manifest_path, manifest_digest, controller_result
    );
    if (length < 0 || (size_t)length >= ARRAYSIZE(command)) return 0;
    ZeroMemory(&startup, sizeof(startup));
    startup.cb = sizeof(startup);
    ZeroMemory(&process, sizeof(process));
    if (!CreateProcessW(
            CONTROLLER_PATH, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
            NULL, NULL, &startup, &process)) {
        return 0;
    }
    CloseHandle(process.hThread);
    waited = WaitForSingleObject(process.hProcess, 90000);
    if (waited != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 95);
        WaitForSingleObject(process.hProcess, 10000);
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

static int production_probe(const wchar_t *result_path) {
    wchar_t manifest_path[32768];
    wchar_t controller_result[32768];
    wchar_t orchestrator_result[32768];
    char manifest_digest[65] = {0};
    char controller_result_digest[65] = {0};
    char orchestrator_result_digest[65] = {0};
    uint64_t ignored_length = 0;
    DWORD controller_exit = STILL_ACTIVE;
    int controller_started = 0;
    int controller_result_present = 0;
    int controller_manifest_verified = 0;
    int controller_timed_out_false = 0;
    int controller_orchestrator_exit_zero = 0;
    int controller_orchestrator_exit_one = 0;
    int controller_orchestrator_exit_seventy_one = 0;
    int controller_completed = 0;
    int controller_verified = 0;
    int orchestrator_result_present = 0;
    int orchestrator_binding_verified = 0;
    int orchestrator_run_id_verified = 0;
    int orchestrator_schema_verified = 0;
    int orchestrator_system_verified = 0;
    int orchestrator_observer_verified = 0;
    int orchestrator_control_verified = 0;
    int orchestrator_acl_applied = 0;
    int orchestrator_pre_observer_completed = 0;
    int orchestrator_allowed_child_completed = 0;
    int orchestrator_post_observer_completed = 0;
    int orchestrator_selective_control = 0;
    int orchestrator_sequence_verified = 0;
    int orchestrator_completed = 0;
    int orchestrator_verified = 0;
    int completed = 0;
    char manifest[1024];
    int manifest_len;
    char output[8192];
    int output_len;

    if (!safe_path_arg(result_path)) return 20;
    if (swprintf(manifest_path, ARRAYSIZE(manifest_path), L"%ls.manifest.json", result_path) < 0 ||
        swprintf(controller_result, ARRAYSIZE(controller_result), L"%ls.controller.json", result_path) < 0 ||
        swprintf(orchestrator_result, ARRAYSIZE(orchestrator_result), L"%ls.controller.json.orchestrator.json", result_path) < 0) {
        return 21;
    }
    DeleteFileW(manifest_path);
    DeleteFileW(controller_result);
    DeleteFileW(orchestrator_result);

    manifest_len = snprintf(
        manifest, sizeof(manifest),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.p1-orchestrator-manifest\","
        "\"runId\":\"%s\",\"action\":\"maintained-control-self-test\","
        "\"networkMode\":\"deny-all-at-hypervisor\","
        "\"stagingExecutionControl\":\"ntfs-inherited-execute-deny\","
        "\"executionControlDigest\":\"%s\","
        "\"thirdPartySampleExecution\":false}\n",
        RUN_ID_A, CONTROL_DIGEST
    );
    if (manifest_len <= 0 || (size_t)manifest_len >= sizeof(manifest) ||
        !write_bytes(manifest_path, manifest, (DWORD)manifest_len)) {
        return 22;
    }
    if (!sha256_file(manifest_path, manifest_digest, &ignored_length)) return 23;

    controller_started = run_controller(
        manifest_path, manifest_digest, controller_result, &controller_exit
    );
    controller_result_present = file_exists(controller_result);
    orchestrator_result_present = file_exists(orchestrator_result);
    if (controller_result_present) {
        sha256_file(controller_result, controller_result_digest, &ignored_length);
        controller_manifest_verified =
            file_contains(controller_result, "\"manifestDigestVerified\":true");
        controller_timed_out_false =
            file_contains(controller_result, "\"timedOut\":false");
        controller_orchestrator_exit_zero =
            file_contains(controller_result, "\"orchestratorExitCode\":0");
        controller_orchestrator_exit_one =
            file_contains(controller_result, "\"orchestratorExitCode\":1");
        controller_orchestrator_exit_seventy_one =
            file_contains(controller_result, "\"orchestratorExitCode\":71");
        controller_completed =
            file_contains(controller_result, "\"completed\":true");
    }
    if (orchestrator_result_present) {
        sha256_file(orchestrator_result, orchestrator_result_digest, &ignored_length);
        orchestrator_binding_verified =
            file_contains(orchestrator_result, "\"bindingDigestVerified\":true");
        orchestrator_run_id_verified =
            file_contains(orchestrator_result, "\"manifestRunIdVerified\":true");
        orchestrator_schema_verified =
            file_contains(orchestrator_result, "\"manifestSchemaVerified\":true");
        orchestrator_system_verified =
            file_contains(orchestrator_result, "\"systemIdentityVerified\":true");
        orchestrator_observer_verified =
            file_contains(orchestrator_result, "\"observerIdentityVerified\":true");
        orchestrator_control_verified =
            file_contains(orchestrator_result, "\"executionControlIdentityVerified\":true");
        orchestrator_acl_applied =
            file_contains(orchestrator_result, "\"aclApplied\":true");
        orchestrator_pre_observer_completed =
            file_contains(orchestrator_result, "\"preObserverCompleted\":true");
        orchestrator_allowed_child_completed =
            file_contains(orchestrator_result, "\"allowedChildCompleted\":true");
        orchestrator_post_observer_completed =
            file_contains(orchestrator_result, "\"postObserverCompleted\":true");
        orchestrator_selective_control =
            file_contains(orchestrator_result, "\"selectiveExecutionControl\":true");
        orchestrator_sequence_verified =
            file_contains(orchestrator_result, "\"observationSequenceVerified\":true");
        orchestrator_completed =
            file_contains(orchestrator_result, "\"completed\":true");
    }
    controller_verified =
        controller_started && controller_exit == 0 && controller_result_present &&
        controller_manifest_verified && controller_timed_out_false &&
        controller_orchestrator_exit_zero && controller_completed;
    orchestrator_verified =
        orchestrator_result_present && orchestrator_binding_verified &&
        orchestrator_run_id_verified && orchestrator_schema_verified &&
        orchestrator_system_verified && orchestrator_observer_verified &&
        orchestrator_control_verified && orchestrator_acl_applied &&
        orchestrator_pre_observer_completed && orchestrator_allowed_child_completed &&
        orchestrator_post_observer_completed && orchestrator_selective_control &&
        orchestrator_sequence_verified && orchestrator_completed &&
        file_contains(orchestrator_result, "\"networkRequested\":false") &&
        file_contains(orchestrator_result, "\"thirdPartySampleExecuted\":false");
    completed = controller_verified && orchestrator_verified;

    output_len = snprintf(
        output, sizeof(output),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.p1-orchestrator-production-probe-result\","
        "\"fixtureId\":\"ordivon-p1-orchestrator-production-probe-v1\","
        "\"runId\":\"%s\",\"manifestDigest\":\"sha256:%s\","
        "\"controllerPath\":\"C:\\\\ProgramData\\\\Ordivon\\\\p1-controller.exe\","
        "\"controllerStarted\":%s,\"controllerExitCode\":%lu,"
        "\"controllerResultPresent\":%s,\"controllerManifestDigestVerified\":%s,"
        "\"controllerTimedOutFalse\":%s,\"controllerOrchestratorExitZero\":%s,"
        "\"controllerOrchestratorExitOne\":%s,\"controllerOrchestratorExitSeventyOne\":%s,"
        "\"controllerCompleted\":%s,\"controllerProductionPathVerified\":%s,"
        "\"controllerResultDigest\":\"sha256:%s\","
        "\"orchestratorPath\":\"C:\\\\ProgramData\\\\Ordivon\\\\p1-orchestrator.ps1\","
        "\"orchestratorResultPresent\":%s,\"orchestratorBindingDigestVerified\":%s,"
        "\"orchestratorRunIdVerified\":%s,\"orchestratorSchemaVerified\":%s,"
        "\"orchestratorSystemIdentityVerified\":%s,\"orchestratorObserverIdentityVerified\":%s,"
        "\"orchestratorExecutionControlIdentityVerified\":%s,\"orchestratorAclApplied\":%s,"
        "\"orchestratorPreObserverCompleted\":%s,\"orchestratorAllowedChildCompleted\":%s,"
        "\"orchestratorPostObserverCompleted\":%s,\"orchestratorSelectiveExecutionControl\":%s,"
        "\"orchestratorObservationSequenceVerified\":%s,\"orchestratorCompleted\":%s,"
        "\"orchestratorResultVerified\":%s,\"orchestratorResultDigest\":\"sha256:%s\","
        "\"networkRequested\":false,\"thirdPartySampleExecuted\":false,"
        "\"completed\":%s}\n",
        RUN_ID_A, manifest_digest,
        controller_started ? "true" : "false", (unsigned long)controller_exit,
        controller_result_present ? "true" : "false",
        controller_manifest_verified ? "true" : "false",
        controller_timed_out_false ? "true" : "false",
        controller_orchestrator_exit_zero ? "true" : "false",
        controller_orchestrator_exit_one ? "true" : "false",
        controller_orchestrator_exit_seventy_one ? "true" : "false",
        controller_completed ? "true" : "false",
        controller_verified ? "true" : "false", controller_result_digest,
        orchestrator_result_present ? "true" : "false",
        orchestrator_binding_verified ? "true" : "false",
        orchestrator_run_id_verified ? "true" : "false",
        orchestrator_schema_verified ? "true" : "false",
        orchestrator_system_verified ? "true" : "false",
        orchestrator_observer_verified ? "true" : "false",
        orchestrator_control_verified ? "true" : "false",
        orchestrator_acl_applied ? "true" : "false",
        orchestrator_pre_observer_completed ? "true" : "false",
        orchestrator_allowed_child_completed ? "true" : "false",
        orchestrator_post_observer_completed ? "true" : "false",
        orchestrator_selective_control ? "true" : "false",
        orchestrator_sequence_verified ? "true" : "false",
        orchestrator_completed ? "true" : "false",
        orchestrator_verified ? "true" : "false", orchestrator_result_digest,
        completed ? "true" : "false"
    );
    if (output_len <= 0 || (size_t)output_len >= sizeof(output) ||
        !write_bytes(result_path, output, (DWORD)output_len)) {
        return 24;
    }
    return completed ? 0 : 25;
}

int wmain(int argc, wchar_t **argv) {
    if (argc == 3 && wcscmp(argv[1], L"--result") == 0) {
        return production_probe(argv[2]);
    }
    return 64;
}
