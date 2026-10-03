#include <windows.h>
#include <winhttp.h>
#include <string.h>
#include <limits.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    char *host = NULL;
    char *path = NULL;
    wchar_t *wide_host = NULL;
    wchar_t *wide_path = NULL;
    size_t endpoint_length;
    size_t authority_start;
    size_t authority_end;
    size_t host_start;
    size_t host_length;
    size_t path_length;
    size_t token_length;
    size_t i;
    unsigned long port = 0;
    int secure;
    int host_chars;
    int path_chars;
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    DWORD flags;
    int result = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    endpoint_length = strlen(endpoint);
    token_length = strlen(token_json);
    if (endpoint_length == 0 || endpoint_length > (size_t)INT_MAX ||
        token_length > (size_t)MAXDWORD)
        return -1;

    if (_strnicmp(endpoint, "https://", 8) == 0) {
        secure = 1;
        authority_start = 8;
    } else if (_strnicmp(endpoint, "http://", 7) == 0) {
        secure = 0;
        authority_start = 7;
    } else {
        return -1;
    }

    authority_end = authority_start;
    while (authority_end < endpoint_length &&
           endpoint[authority_end] != '/' &&
           endpoint[authority_end] != '?' &&
           endpoint[authority_end] != '#')
        ++authority_end;

    if (authority_end == authority_start)
        return -1;

    host_start = authority_start;
    if (endpoint[host_start] == '[') {
        size_t closing_bracket = host_start + 1;
        while (closing_bracket < authority_end &&
               endpoint[closing_bracket] != ']')
            ++closing_bracket;
        if (closing_bracket == authority_end || closing_bracket == host_start + 1)
            return -1;

        host_start++;
        host_length = closing_bracket - host_start;
        if (closing_bracket + 1 < authority_end) {
            if (endpoint[closing_bracket + 1] != ':')
                return -1;
            i = closing_bracket + 2;
            if (i == authority_end)
                return -1;
            for (; i < authority_end; ++i) {
                if (endpoint[i] < '0' || endpoint[i] > '9')
                    return -1;
                port = port * 10UL + (unsigned long)(endpoint[i] - '0');
                if (port > 65535UL)
                    return -1;
            }
        }
    } else {
        size_t colon = authority_end;
        for (i = authority_start; i < authority_end; ++i) {
            if (endpoint[i] == '@')
                return -1;
            if (endpoint[i] == ':') {
                if (colon != authority_end)
                    return -1;
                colon = i;
            }
        }

        if (colon == authority_end) {
            host_start = authority_start;
            host_length = authority_end - authority_start;
        } else {
            host_start = authority_start;
            host_length = colon - authority_start;
            if (colon + 1 == authority_end)
                return -1;
            for (i = colon + 1; i < authority_end; ++i) {
                if (endpoint[i] < '0' || endpoint[i] > '9')
                    return -1;
                port = port * 10UL + (unsigned long)(endpoint[i] - '0');
                if (port > 65535UL)
                    return -1;
            }
        }
    }

    if (host_length == 0 || port == 0 && (
            (endpoint[authority_start] == '[' &&
             authority_end > authority_start + 1 &&
             endpoint[authority_end - 1] == ':') ||
            (endpoint[authority_start] != '[' &&
             memchr(endpoint + authority_start, ':',
                    authority_end - authority_start) != NULL)))
        return -1;

    if (port == 0)
        port = secure ? 443UL : 80UL;

    host = (char *)HeapAlloc(GetProcessHeap(), 0, host_length + 1);
    if (host == NULL)
        goto cleanup;
    memcpy(host, endpoint + host_start, host_length);
    host[host_length] = '\0';

    path = (char *)HeapAlloc(GetProcessHeap(), 0, endpoint_length + 2);
    if (path == NULL)
        goto cleanup;

    path_length = 0;
    if (authority_end < endpoint_length && endpoint[authority_end] == '/') {
        size_t end = authority_end;
        while (end < endpoint_length && endpoint[end] != '#')
            ++end;
        path_length = end - authority_end;
        memcpy(path, endpoint + authority_end, path_length);
    } else if (authority_end < endpoint_length && endpoint[authority_end] == '?') {
        size_t end = authority_end;
        path[path_length++] = '/';
        while (end < endpoint_length && endpoint[end] != '#')
            path[path_length++] = endpoint[end++];
    } else {
        path[path_length++] = '/';
    }
    path[path_length] = '\0';

    host_chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     host, (int)host_length, NULL, 0);
    path_chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                     path, (int)path_length, NULL, 0);
    if (host_chars <= 0 || path_chars <= 0)
        goto cleanup;

    wide_host = (wchar_t *)HeapAlloc(GetProcessHeap(), 0,
                                     ((size_t)host_chars + 1) * sizeof(wchar_t));
    wide_path = (wchar_t *)HeapAlloc(GetProcessHeap(), 0,
                                     ((size_t)path_chars + 1) * sizeof(wchar_t));
    if (wide_host == NULL || wide_path == NULL)
        goto cleanup;

    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, host,
                            (int)host_length, wide_host, host_chars) != host_chars ||
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path,
                            (int)path_length, wide_path, path_chars) != path_chars)
        goto cleanup;

    wide_host[host_chars] = L'\0';
    wide_path[path_chars] = L'\0';

    session = WinHttpOpenW(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == NULL)
        goto cleanup;

    connection = WinHttpConnect(session, wide_host, (INTERNET_PORT)port, 0);
    if (connection == NULL)
        goto cleanup;

    flags = secure ? WINHTTP_FLAG_SECURE : 0;
    request = WinHttpOpenRequest(connection, L"POST", wide_path, NULL,
                                 WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (request == NULL)
        goto cleanup;

    if (!WinHttpSendRequest(request, L"Content-Type: application/json\r\n",
                            (DWORD)-1, (LPVOID)token_json,
                            (DWORD)token_length, (DWORD)token_length, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(request, NULL))
        goto cleanup;

    if (!WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE |
                                 WINHTTP_QUERY_FLAG_NUMBER,
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
    if (wide_path != NULL)
        HeapFree(GetProcessHeap(), 0, wide_path);
    if (wide_host != NULL)
        HeapFree(GetProcessHeap(), 0, wide_host);
    if (path != NULL)
        HeapFree(GetProcessHeap(), 0, path);
    if (host != NULL)
        HeapFree(GetProcessHeap(), 0, host);

    return result;
}