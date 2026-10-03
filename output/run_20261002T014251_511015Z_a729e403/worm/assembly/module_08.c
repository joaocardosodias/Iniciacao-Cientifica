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
#include <wchar.h>
#include <limits.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    int result = -1;
    size_t endpoint_length;
    size_t token_length;
    int wide_length;
    wchar_t *wide_endpoint = NULL;
    wchar_t *host = NULL;
    wchar_t *request_path = NULL;
    size_t url_length;
    size_t scheme_end;
    size_t authority_start;
    size_t authority_end;
    size_t host_start;
    size_t host_end;
    size_t port_start = 0;
    size_t path_end;
    size_t path_length;
    size_t i;
    unsigned long port_number = 0;
    INTERNET_PORT port;
    DWORD request_flags = 0;
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    const wchar_t *content_type = L"Content-Type: application/json\r\n";

    if (endpoint == NULL || token_json == NULL)
        goto cleanup;

    endpoint_length = strlen(endpoint);
    token_length = strlen(token_json);
    if (endpoint_length == 0 || endpoint_length >= (size_t)INT_MAX ||
        token_length > 0xFFFFFFFFUL)
        goto cleanup;

    wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, endpoint,
                                      (int)endpoint_length, NULL, 0);
    if (wide_length <= 0)
        goto cleanup;

    wide_endpoint = (wchar_t *)malloc(((size_t)wide_length + 1) * sizeof(wchar_t));
    if (wide_endpoint == NULL)
        goto cleanup;

    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, endpoint,
                            (int)endpoint_length, wide_endpoint, wide_length) != wide_length)
        goto cleanup;
    wide_endpoint[wide_length] = L'\0';
    url_length = (size_t)wide_length;

    scheme_end = 0;
    while (scheme_end < url_length && wide_endpoint[scheme_end] != L':')
        ++scheme_end;
    if (scheme_end == 4 &&
        (wide_endpoint[0] == L'h' || wide_endpoint[0] == L'H') &&
        (wide_endpoint[1] == L't' || wide_endpoint[1] == L'T') &&
        (wide_endpoint[2] == L't' || wide_endpoint[2] == L'T') &&
        (wide_endpoint[3] == L'p' || wide_endpoint[3] == L'P')) {
        port = INTERNET_DEFAULT_HTTP_PORT;
    } else if (scheme_end == 5 &&
               (wide_endpoint[0] == L'h' || wide_endpoint[0] == L'H') &&
               (wide_endpoint[1] == L't' || wide_endpoint[1] == L'T') &&
               (wide_endpoint[2] == L't' || wide_endpoint[2] == L'T') &&
               (wide_endpoint[3] == L'p' || wide_endpoint[3] == L'P') &&
               (wide_endpoint[4] == L's' || wide_endpoint[4] == L'S')) {
        port = INTERNET_DEFAULT_HTTPS_PORT;
        request_flags = WINHTTP_FLAG_SECURE;
    } else {
        goto cleanup;
    }

    if (scheme_end + 3 > url_length ||
        wide_endpoint[scheme_end + 1] != L'/' ||
        wide_endpoint[scheme_end + 2] != L'/')
        goto cleanup;

    authority_start = scheme_end + 3;
    authority_end = authority_start;
    while (authority_end < url_length &&
           wide_endpoint[authority_end] != L'/' &&
           wide_endpoint[authority_end] != L'?' &&
           wide_endpoint[authority_end] != L'#')
        ++authority_end;

    if (authority_end == authority_start)
        goto cleanup;

    for (i = authority_start; i < authority_end; ++i) {
        wchar_t c = wide_endpoint[i];
        if (c <= L' ' || c == L'@' || c == L'\\')
            goto cleanup;
    }

    host_start = authority_start;
    host_end = authority_end;

    if (wide_endpoint[authority_start] == L'[') {
        size_t closing_bracket = authority_start + 1;
        while (closing_bracket < authority_end &&
               wide_endpoint[closing_bracket] != L']')
            ++closing_bracket;
        if (closing_bracket == authority_end || closing_bracket == authority_start + 1)
            goto cleanup;
        host_start = authority_start + 1;
        host_end = closing_bracket;
        if (closing_bracket + 1 < authority_end) {
            if (wide_endpoint[closing_bracket + 1] != L':')
                goto cleanup;
            port_start = closing_bracket + 2;
        } else if (closing_bracket + 1 == authority_end) {
            port_start = 0;
        }
    } else {
        size_t colon = authority_end;
        for (i = authority_start; i < authority_end; ++i) {
            if (wide_endpoint[i] == L':') {
                if (colon != authority_end)
                    goto cleanup;
                colon = i;
            } else if (wide_endpoint[i] == L'[' || wide_endpoint[i] == L']') {
                goto cleanup;
            }
        }
        if (colon != authority_end) {
            host_end = colon;
            port_start = colon + 1;
        }
    }

    if (host_end <= host_start)
        goto cleanup;

    if (port_start != 0) {
        if (port_start >= authority_end)
            goto cleanup;
        for (i = port_start; i < authority_end; ++i) {
            if (wide_endpoint[i] < L'0' || wide_endpoint[i] > L'9')
                goto cleanup;
            port_number = port_number * 10UL +
                         (unsigned long)(wide_endpoint[i] - L'0');
            if (port_number > 65535UL)
                goto cleanup;
        }
        if (port_number == 0)
            goto cleanup;
        port = (INTERNET_PORT)port_number;
    }

    for (i = host_start; i < host_end; ++i) {
        wchar_t c = wide_endpoint[i];
        if (c <= L' ' || c == L'/' || c == L'?' || c == L'#' ||
            c == L'@' || c == L'\\' || c == L'[' || c == L']')
            goto cleanup;
    }

    host = (wchar_t *)malloc((host_end - host_start + 1) * sizeof(wchar_t));
    if (host == NULL)
        goto cleanup;
    memcpy(host, wide_endpoint + host_start,
           (host_end - host_start) * sizeof(wchar_t));
    host[host_end - host_start] = L'\0';

    path_end = authority_end;
    while (path_end < url_length && wide_endpoint[path_end] != L'#')
        ++path_end;

    if (authority_end < path_end && wide_endpoint[authority_end] == L'?') {
        path_length = path_end - authority_end;
        request_path = (wchar_t *)malloc((path_length + 2) * sizeof(wchar_t));
        if (request_path == NULL)
            goto cleanup;
        request_path[0] = L'/';
        memcpy(request_path + 1, wide_endpoint + authority_end,
               path_length * sizeof(wchar_t));
        request_path[path_length + 1] = L'\0';
    } else if (authority_end < path_end && wide_endpoint[authority_end] == L'/') {
        path_length = path_end - authority_end;
        request_path = (wchar_t *)malloc((path_length + 1) * sizeof(wchar_t));
        if (request_path == NULL)
            goto cleanup;
        memcpy(request_path, wide_endpoint + authority_end,
               path_length * sizeof(wchar_t));
        request_path[path_length] = L'\0';
    } else {
        request_path = (wchar_t *)malloc(2 * sizeof(wchar_t));
        if (request_path == NULL)
            goto cleanup;
        request_path[0] = L'/';
        request_path[1] = L'\0';
    }

    for (i = 0; request_path[i] != L'\0'; ++i) {
        if (request_path[i] <= L' ' || request_path[i] == 0x7F ||
            request_path[i] == L'\\')
            goto cleanup;
    }

    session = WinHttpOpenW(L"transmit_token/1.0",
                           WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS,
                           0);
    if (session == NULL)
        goto cleanup;

    connection = WinHttpConnectW(session, host, port, 0);
    if (connection == NULL)
        goto cleanup;

    request = WinHttpOpenRequestW(connection, L"POST", request_path,
                                  NULL, WINHTTP_NO_REFERER,
                                  WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  request_flags);
    if (request == NULL)
        goto cleanup;

    if (!WinHttpSendRequest(request, content_type, (DWORD)-1L,
                            (LPVOID)token_json, (DWORD)token_length,
                            (DWORD)token_length, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(request, NULL))
        goto cleanup;

    if (!WinHttpQueryHeadersW(request,
                              WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                              WINHTTP_HEADER_NAME_BY_INDEX,
                              &status_code, &status_size,
                              WINHTTP_NO_HEADER_INDEX))
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
    free(request_path);
    free(host);
    free(wide_endpoint);
    return result;
}