#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    const char *authority;
    const char *authority_end;
    const char *host_start;
    const char *host_end;
    const char *port_start = NULL;
    const char *path_start;
    const char *path_end;
    const char *p;
    size_t host_length;
    size_t path_length;
    size_t endpoint_length;
    size_t body_length;
    unsigned long port_value = 0;
    INTERNET_PORT port;
    BOOL secure;
    char *host_ansi = NULL;
    char *path_ansi = NULL;
    WCHAR *host_wide = NULL;
    WCHAR *path_wide = NULL;
    int host_wide_length;
    int path_wide_length;
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    DWORD request_flags = 0;
    int result = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    endpoint_length = strlen(endpoint);
    body_length = strlen(token_json);
    if (endpoint_length > INT_MAX || body_length > MAXDWORD)
        return -1;

    if (endpoint_length >= 7 &&
        endpoint[0] == 'h' && endpoint[1] == 't' &&
        endpoint[2] == 't' && endpoint[3] == 'p' &&
        endpoint[4] == ':' && endpoint[5] == '/' &&
        endpoint[6] == '/') {
        secure = FALSE;
        authority = endpoint + 7;
    } else if (endpoint_length >= 8 &&
               endpoint[0] == 'h' && endpoint[1] == 't' &&
               endpoint[2] == 't' && endpoint[3] == 'p' &&
               endpoint[4] == 's' && endpoint[5] == ':' &&
               endpoint[6] == '/' && endpoint[7] == '/') {
        secure = TRUE;
        authority = endpoint + 8;
    } else if (endpoint_length >= 7 &&
               endpoint[0] == 'H' && endpoint[1] == 'T' &&
               endpoint[2] == 'T' && endpoint[3] == 'P' &&
               endpoint[4] == ':' && endpoint[5] == '/' &&
               endpoint[6] == '/') {
        secure = FALSE;
        authority = endpoint + 7;
    } else if (endpoint_length >= 8 &&
               endpoint[0] == 'H' && endpoint[1] == 'T' &&
               endpoint[2] == 'T' && endpoint[3] == 'P' &&
               endpoint[4] == 'S' && endpoint[5] == ':' &&
               endpoint[6] == '/' && endpoint[7] == '/') {
        secure = TRUE;
        authority = endpoint + 8;
    } else {
        return -1;
    }

    authority_end = authority;
    while (*authority_end != '\0' && *authority_end != '/' &&
           *authority_end != '?' && *authority_end != '#')
        ++authority_end;

    if (authority == authority_end ||
        memchr(authority, '@', (size_t)(authority_end - authority)) != NULL)
        return -1;

    if (*authority == '[') {
        const char *closing_bracket = memchr(authority + 1, ']',
                                             (size_t)(authority_end - authority - 1));
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
        host_start = authority;
        host_end = authority_end;
        for (p = authority; p < authority_end; ++p) {
            if (*p == ':') {
                if (colon != NULL)
                    return -1;
                colon = p;
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
        if (port_start >= authority_end)
            return -1;
        for (p = port_start; p < authority_end; ++p) {
            if (*p < '0' || *p > '9')
                return -1;
            port_value = port_value * 10UL + (unsigned long)(*p - '0');
            if (port_value > 65535UL)
                return -1;
        }
        if (port_value == 0)
            return -1;
        port = (INTERNET_PORT)port_value;
    } else {
        port = secure ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    }

    host_length = (size_t)(host_end - host_start);
    host_ansi = (char *)malloc(host_length + 1);
    if (host_ansi == NULL)
        goto cleanup;
    memcpy(host_ansi, host_start, host_length);
    host_ansi[host_length] = '\0';

    path_start = authority_end;
    if (*path_start == '/') {
        path_end = path_start;
        while (*path_end != '\0' && *path_end != '#')
            ++path_end;
        path_length = (size_t)(path_end - path_start);
        path_ansi = (char *)malloc(path_length + 1);
        if (path_ansi == NULL)
            goto cleanup;
        memcpy(path_ansi, path_start, path_length);
        path_ansi[path_length] = '\0';
    } else if (*path_start == '?') {
        path_end = path_start;
        while (*path_end != '\0' && *path_end != '#')
            ++path_end;
        path_length = (size_t)(path_end - path_start) + 1;
        path_ansi = (char *)malloc(path_length + 1);
        if (path_ansi == NULL)
            goto cleanup;
        path_ansi[0] = '/';
        memcpy(path_ansi + 1, path_start, path_length - 1);
        path_ansi[path_length] = '\0';
    } else {
        path_ansi = (char *)malloc(2);
        if (path_ansi == NULL)
            goto cleanup;
        path_ansi[0] = '/';
        path_ansi[1] = '\0';
        path_length = 1;
    }

    host_wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           host_ansi, -1, NULL, 0);
    path_wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           path_ansi, -1, NULL, 0);
    if (host_wide_length <= 0 || path_wide_length <= 0)
        goto cleanup;

    host_wide = (WCHAR *)malloc((size_t)host_wide_length * sizeof(WCHAR));
    path_wide = (WCHAR *)malloc((size_t)path_wide_length * sizeof(WCHAR));
    if (host_wide == NULL || path_wide == NULL)
        goto cleanup;

    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host_ansi, -1,
                            host_wide, host_wide_length) == 0 ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path_ansi, -1,
                            path_wide, path_wide_length) == 0)
        goto cleanup;

    session = WinHttpOpen(L"transmit_token",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS,
                          0);
    if (session == NULL)
        goto cleanup;

    connection = WinHttpConnect(session, host_wide, port, 0);
    if (connection == NULL)
        goto cleanup;

    if (secure)
        request_flags |= WINHTTP_FLAG_SECURE;

    request = WinHttpOpenRequest(connection, L"POST", path_wide,
                                 NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 request_flags);
    if (request == NULL)
        goto cleanup;

    if (!WinHttpSendRequest(request,
                            L"Content-Type: application/json\r\n",
                            (DWORD)-1,
                            (LPVOID)token_json,
                            (DWORD)body_length,
                            (DWORD)body_length,
                            0))
        goto cleanup;

    if (!WinHttpReceiveResponse(request, NULL))
        goto cleanup;

    if (!WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX,
                             &status_code,
                             &status_size,
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
    free(path_wide);
    free(host_wide);
    free(path_ansi);
    free(host_ansi);
    return result;
}