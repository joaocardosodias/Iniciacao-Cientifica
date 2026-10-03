#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    char *host = NULL;
    char *path = NULL;
    const char *authority;
    const char *authority_end;
    const char *host_start;
    const char *host_end;
    const char *port_start = NULL;
    const char *path_start;
    const char *path_end;
    size_t host_length;
    size_t path_length;
    size_t body_length;
    DWORD body_length_dw;
    INTERNET_PORT port;
    DWORD request_flags = 0;
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    BOOL secure;
    int result = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    if (_strnicmp(endpoint, "http://", 7) == 0) {
        authority = endpoint + 7;
        port = INTERNET_DEFAULT_HTTP_PORT;
        secure = FALSE;
    } else if (_strnicmp(endpoint, "https://", 8) == 0) {
        authority = endpoint + 8;
        port = INTERNET_DEFAULT_HTTPS_PORT;
        secure = TRUE;
        request_flags = WINHTTP_FLAG_SECURE;
    } else {
        return -1;
    }

    authority_end = strpbrk(authority, "/?#");
    if (authority_end == NULL)
        authority_end = authority + strlen(authority);
    if (authority == authority_end || memchr(authority, '@', (size_t)(authority_end - authority)) != NULL)
        return -1;

    if (*authority == '[') {
        const char *closing_bracket = memchr(authority + 1, ']', (size_t)(authority_end - authority - 1));
        if (closing_bracket == NULL || closing_bracket == authority + 1)
            return -1;
        host_start = authority + 1;
        host_end = closing_bracket;
        if (closing_bracket + 1 < authority_end) {
            if (closing_bracket[1] != ':')
                return -1;
            port_start = closing_bracket + 2;
        }
    } else {
        const char *colon = NULL;
        const char *cursor;

        host_start = authority;
        host_end = authority_end;
        for (cursor = authority; cursor < authority_end; ++cursor) {
            if (*cursor == ':') {
                if (colon != NULL)
                    return -1;
                colon = cursor;
            }
        }
        if (colon != NULL) {
            host_end = colon;
            port_start = colon + 1;
        }
    }

    if (host_start == host_end)
        return -1;

    if (port_start != NULL) {
        unsigned long parsed_port = 0;
        const char *cursor;

        if (port_start >= authority_end)
            return -1;
        for (cursor = port_start; cursor < authority_end; ++cursor) {
            if (*cursor < '0' || *cursor > '9')
                return -1;
            parsed_port = parsed_port * 10 + (unsigned long)(*cursor - '0');
            if (parsed_port > 65535)
                return -1;
        }
        if (parsed_port == 0)
            return -1;
        port = (INTERNET_PORT)parsed_port;
    }

    host_length = (size_t)(host_end - host_start);
    host = (char *)malloc(host_length + 1);
    if (host == NULL)
        goto cleanup;
    memcpy(host, host_start, host_length);
    host[host_length] = '\0';

    path_start = authority_end;
    path_end = path_start + strlen(path_start);
    {
        const char *fragment = memchr(path_start, '#', (size_t)(path_end - path_start));
        if (fragment != NULL)
            path_end = fragment;
    }

    if (path_start == path_end || *path_start == '#') {
        path_length = 1;
        path = (char *)malloc(2);
        if (path == NULL)
            goto cleanup;
        path[0] = '/';
        path[1] = '\0';
    } else if (*path_start == '?') {
        path_length = (size_t)(path_end - path_start);
        path = (char *)malloc(path_length + 2);
        if (path == NULL)
            goto cleanup;
        path[0] = '/';
        memcpy(path + 1, path_start, path_length);
        path[path_length + 1] = '\0';
    } else {
        path_length = (size_t)(path_end - path_start);
        path = (char *)malloc(path_length + 1);
        if (path == NULL)
            goto cleanup;
        memcpy(path, path_start, path_length);
        path[path_length] = '\0';
    }

    body_length = strlen(token_json);
    if (body_length > MAXDWORD)
        goto cleanup;
    body_length_dw = (DWORD)body_length;

    session = WinHttpOpenA("transmit_token", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == NULL)
        goto cleanup;

    connection = WinHttpConnectA(session, host, port, 0);
    if (connection == NULL)
        goto cleanup;

    request = WinHttpOpenRequestA(connection, "POST", path, NULL, NULL,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES, request_flags);
    if (request == NULL)
        goto cleanup;

    if (!WinHttpSendRequestA(request, "Content-Type: application/json\r\n",
                             (DWORD)-1, (LPVOID)token_json, body_length_dw,
                             body_length_dw, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(request, NULL))
        goto cleanup;

    if (!WinHttpQueryHeadersA(request,
                              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              WINHTTP_HEADER_NAME_BY_INDEX, &status_code,
                              &status_size, WINHTTP_NO_HEADER_INDEX))
        goto cleanup;

    if (status_code == 200)
        result = 0;

cleanup:
    if (request != NULL)
        WinHttpCloseHandle(request);
    if (connection != NULL)
        WinHttpCloseHandle(connection);
    if (session != NULL)
        WinHttpCloseHandle(session);
    free(path);
    free(host);
    return result;
}