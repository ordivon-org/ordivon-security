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
        L"New-NetIPAddress -InterfaceIndex $a.ifIndex -IPAddress '10.253.60.2' -PrefixLength 24 -AddressFamily IPv4 -ErrorAction Stop | Out-Null; "
        L"$r=$null; for($i=0;$i -lt 20;$i++){"
        L"$r=Get-NetRoute -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -DestinationPrefix '10.253.60.0/24' -ErrorAction SilentlyContinue | Select-Object -First 1; "
        L"if($null -ne $r){break}; Start-Sleep -Milliseconds 250}; if($null -eq $r){exit 32}\"";
    DWORD configure_exit = 0;
    int configure_result = run_process(configure, 30000, &configure_exit);
    BOOL configured = configure_result == 0 && configure_exit == 0;

    BOOL connected = FALSE;
    BOOL banner_matched = FALSE;
    int socket_error = 0;
    WSADATA wsa = {0};
    if (configured && WSAStartup(MAKEWORD(2, 2), &wsa) == 0) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock != INVALID_SOCKET) {
            DWORD timeout = 5000;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
            struct sockaddr_in address = {0};
            address.sin_family = AF_INET;
            address.sin_port = htons(48080);
            address.sin_addr.s_addr = inet_addr("10.253.60.3");
            if (connect(sock, (struct sockaddr *)&address, sizeof(address)) == 0) {
                connected = TRUE;
                char buffer[128] = {0};
                int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0 && strstr(buffer, "ORDIVON-S5-PEER") != NULL) {
                    banner_matched = TRUE;
                }
            } else {
                socket_error = WSAGetLastError();
            }
            closesocket(sock);
        } else {
            socket_error = WSAGetLastError();
        }
        WSACleanup();
    }

    BOOL completed = configured && connected && banner_matched;
    char result[1024];
    int length = snprintf(
        result,
        sizeof(result),
        "{\"schemaVersion\":1,\"kind\":\"ordivon.security.s5-fabric-canary-result\","
        "\"fixtureId\":\"ordivon-s5-fabric-canary-v1\",\"configuredStaticIpv4\":%s,"
        "\"rangeRoutePresent\":%s,\"guestNicMac\":\"52-54-00-53-35-01\","
        "\"peerConnected\":%s,\"peerBannerMatched\":%s,\"peerAddress\":\"10.253.60.3\","
        "\"peerPort\":48080,\"externalNetworkRequested\":false,\"socketError\":%d,\"completed\":%s}\n",
        configured ? "true" : "false",
        configured ? "true" : "false",
        connected ? "true" : "false",
        banner_matched ? "true" : "false",
        socket_error,
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
