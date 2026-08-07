#include <winsock2.h>
#include <ws2tcpip.h>
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

static int run_process(const wchar_t *command, DWORD timeout_ms, DWORD *exit_code) {
    wchar_t mutable_command[8192];
    if (wcslen(command) >= (sizeof(mutable_command) / sizeof(mutable_command[0]))) {
        return 1;
    }
    wcscpy(mutable_command, command);
    STARTUPINFOW startup = {0};
    PROCESS_INFORMATION process = {0};
    startup.cb = sizeof(startup);
    BOOL created = CreateProcessW(NULL, mutable_command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                                  NULL, NULL, &startup, &process);
    if (!created) {
        return 2;
    }
    DWORD waited = WaitForSingleObject(process.hProcess, timeout_ms);
    if (waited != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 90);
        WaitForSingleObject(process.hProcess, 5000);
    }
    if (exit_code != NULL) {
        GetExitCodeProcess(process.hProcess, exit_code);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return waited == WAIT_OBJECT_0 ? 0 : 3;
}

static BOOL connect_banner(const char *address_text, unsigned short port, const char *expected,
                           int attempts, int *last_error) {
    for (int attempt = 0; attempt < attempts; attempt++) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            *last_error = WSAGetLastError();
            return FALSE;
        }
        DWORD timeout = 3000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
        struct sockaddr_in address = {0};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = inet_addr(address_text);
        if (connect(sock, (struct sockaddr *)&address, sizeof(address)) == 0) {
            char buffer[128] = {0};
            int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
            closesocket(sock);
            if (received > 0 && strstr(buffer, expected) != NULL) {
                *last_error = 0;
                return TRUE;
            }
            *last_error = received <= 0 ? WSAGetLastError() : 0;
        } else {
            *last_error = WSAGetLastError();
            closesocket(sock);
        }
        Sleep(500);
    }
    return FALSE;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 3 || wcscmp(argv[1], L"--result") != 0) {
        return 64;
    }

    const wchar_t *configure =
        L"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command \""
        L"$a=Get-NetAdapter -IncludeHidden | Where-Object {$_.MacAddress -eq '52-54-00-53-35-01'} | Select-Object -First 1; "
        L"if($null -eq $a){exit 31}; "
        L"Set-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction SilentlyContinue; "
        L"Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        L"Where-Object {$_.IPAddress -ne '127.0.0.1'} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; "
        L"New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress '10.253.70.2' -PrefixLength 24 -AddressFamily IPv4 -ErrorAction Stop | Out-Null; "
        L"$r=$null; for($i=0;$i -lt 20;$i++){"
        L"$r=Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -DestinationPrefix '10.253.70.0/24' -ErrorAction SilentlyContinue | Select-Object -First 1; "
        L"if($null -ne $r){break}; Start-Sleep -Milliseconds 250}; if($null -eq $r){exit 32}\"";
    DWORD configure_exit = 0;
    int configure_result = run_process(configure, 30000, &configure_exit);
    BOOL configured = configure_result == 0 && configure_exit == 0;

    BOOL peer_a = FALSE;
    BOOL peer_b = FALSE;
    int peer_a_error = 0;
    int peer_b_error = 0;
    WSADATA wsa = {0};
    if (configured && WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
        peer_a = connect_banner("10.253.70.3", 48080, "ORDIVON-S6-PEER-A", 40, &peer_a_error);
        if (peer_a) {
            peer_b = connect_banner("10.253.70.4", 48080, "ORDIVON-S6-PEER-B", 120, &peer_b_error);
        }
        WSACleanup();
    }

    BOOL completed = configured && peer_a && peer_b;
    char result[1400];
    int length = snprintf(
        result,
        sizeof(result),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.s6-topology-churn-canary-result\","
        "\"fixtureId\":\"ordivon-s6-topology-churn-canary-v1\",\"configuredStaticIpv4\":%s,"
        "\"rangeRoutePresent\":%s,\"guestNicMac\":\"52-54-00-53-35-01\","
        "\"peerAAddress\":\"10.253.70.3\",\"peerAPort\":48080,\"peerAConnected\":%s,"
        "\"peerABannerMatched\":%s,\"peerASocketError\":%d,"
        "\"peerBAddress\":\"10.253.70.4\",\"peerBPort\":48080,\"peerBConnected\":%s,"
        "\"peerBBannerMatched\":%s,\"peerBSocketError\":%d,"
        "\"externalNetworkRequested\":false,\"completed\":%s}\n",
        configured ? "true" : "false",
        configured ? "true" : "false",
        peer_a ? "true" : "false",
        peer_a ? "true" : "false",
        peer_a_error,
        peer_b ? "true" : "false",
        peer_b ? "true" : "false",
        peer_b_error,
        completed ? "true" : "false"
    );
    if (length < 0 || length >= (int)sizeof(result)) {
        return 65;
    }
    if (write_text(argv[2], result) != 0) {
        return 66;
    }
    return completed ? 0 : 67;
}
