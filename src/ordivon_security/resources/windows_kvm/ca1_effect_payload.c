#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>

static const char EFFECT_BYTES[] = "ordivon-ca1-same-effect-v1\n";

static int safe_path(const wchar_t *value) {
    const wchar_t *p;
    if (value == NULL || *value == L'\0') return 0;
    for (p = value; *p; ++p) {
        if (*p == L'\"' || *p == L'\r' || *p == L'\n') return 0;
    }
    return 1;
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

static DWORD parent_pid(void) {
    HANDLE snap;
    PROCESSENTRY32W entry;
    DWORD self = GetCurrentProcessId();
    DWORD parent = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    ZeroMemory(&entry, sizeof(entry));
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            if (entry.th32ProcessID == self) {
                parent = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return parent;
}

static int process_image(DWORD pid, wchar_t *output, DWORD capacity) {
    HANDLE process;
    DWORD size = capacity;
    if (pid == 0 || output == NULL || capacity < 2) return 0;
    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL) return 0;
    output[0] = L'\0';
    if (!QueryFullProcessImageNameW(process, 0, output, &size)) {
        CloseHandle(process);
        return 0;
    }
    CloseHandle(process);
    return 1;
}

static int current_user_sid(wchar_t *output, DWORD capacity) {
    HANDLE token = NULL;
    DWORD needed = 0;
    TOKEN_USER *user = NULL;
    LPWSTR sid_text = NULL;
    int ok = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) goto done;
    GetTokenInformation(token, TokenUser, NULL, 0, &needed);
    if (needed == 0) goto done;
    user = (TOKEN_USER *)HeapAlloc(GetProcessHeap(), 0, needed);
    if (user == NULL) goto done;
    if (!GetTokenInformation(token, TokenUser, user, needed, &needed)) goto done;
    if (!ConvertSidToStringSidW(user->User.Sid, &sid_text)) goto done;
    if (wcslen(sid_text) + 1 > capacity) goto done;
    wcscpy(output, sid_text);
    ok = 1;
done:
    if (sid_text != NULL) LocalFree(sid_text);
    if (user != NULL) HeapFree(GetProcessHeap(), 0, user);
    if (token != NULL) CloseHandle(token);
    return ok;
}

static int wide_json_escape_utf8(const wchar_t *input, char *output, size_t capacity) {
    int bytes;
    char temp[4096];
    size_t i, j = 0;
    if (input == NULL || output == NULL || capacity < 2) return 0;
    bytes = WideCharToMultiByte(CP_UTF8, 0, input, -1, temp, sizeof(temp), NULL, NULL);
    if (bytes <= 0) return 0;
    for (i = 0; temp[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char)temp[i];
        if (ch == '\\' || ch == '\"') {
            if (j + 2 >= capacity) return 0;
            output[j++] = '\\';
            output[j++] = (char)ch;
        } else if (ch == '\r' || ch == '\n' || ch == '\t') {
            if (j + 2 >= capacity) return 0;
            output[j++] = '\\';
            output[j++] = ch == '\r' ? 'r' : (ch == '\n' ? 'n' : 't');
        } else if (ch < 0x20) {
            return 0;
        } else {
            if (j + 1 >= capacity) return 0;
            output[j++] = (char)ch;
        }
    }
    output[j] = '\0';
    return 1;
}

int wmain(int argc, wchar_t **argv) {
    DWORD self_pid;
    DWORD ppid;
    wchar_t parent_image_w[2048] = L"";
    wchar_t sid_w[256] = L"";
    char parent_image[8192] = "";
    char sid[1024] = "";
    char evidence[12288];
    int evidence_len;

    if (argc != 3 || !safe_path(argv[1]) || !safe_path(argv[2])) return 2;
    if (!write_bytes(argv[1], EFFECT_BYTES, (DWORD)(sizeof(EFFECT_BYTES) - 1))) return 3;

    self_pid = GetCurrentProcessId();
    ppid = parent_pid();
    process_image(ppid, parent_image_w, ARRAYSIZE(parent_image_w));
    current_user_sid(sid_w, ARRAYSIZE(sid_w));
    if (!wide_json_escape_utf8(parent_image_w, parent_image, sizeof(parent_image))) return 4;
    if (!wide_json_escape_utf8(sid_w, sid, sizeof(sid))) return 5;

    evidence_len = snprintf(
        evidence, sizeof(evidence),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.ca1-effect-evidence\","
        "\"effectId\":\"ca1-same-effect-v1\",\"markerByteLength\":%u,"
        "\"processId\":%lu,\"parentProcessId\":%lu,"
        "\"parentImage\":\"%s\",\"userSid\":\"%s\","
        "\"networkRequested\":false}\n",
        (unsigned)(sizeof(EFFECT_BYTES) - 1),
        (unsigned long)self_pid, (unsigned long)ppid, parent_image, sid
    );
    if (evidence_len <= 0 || (size_t)evidence_len >= sizeof(evidence)) return 6;
    if (!write_bytes(argv[2], evidence, (DWORD)evidence_len)) return 7;
    return 0;
}
