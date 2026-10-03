#include <windows.h>
#include <winhttp.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    int result = -1;
    int wide_length;
    WCHAR *wide_endpoint = NULL;
    WCHAR *scheme = NULL;
    WCHAR *host = NULL;
    WCHAR *path = NULL;
    WCHAR *extra = NULL;
    WCHAR *target = NULL;
    URL_COMPONENTS components;
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    DWORD body_length;
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    size_t path_length;
    size_t extra_length;
    size_t target_length;
    size_t fragment_offset;
    DWORD request_flags = 0;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    wide_length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, endpoint, -1, NULL, 0);
    if (wide_length <= 0)
        goto cleanup;

    wide_endpoint = (WCHAR *)malloc((size_t)wide_length * sizeof(WCHAR));
    if (wide_endpoint == NULL)
        goto cleanup;

    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, endpoint, -1,
                            wide_endpoint, wide_length) == 0)
        goto cleanup;

    ZeroMemory(&components, sizeof(components));
    components.dwStructLength = sizeof(components);
    if (!WinHttpCrackUrl(wide_endpoint, 0, 0, &components))
        goto cleanup;

    if (components.dwSchemeLength == 0 || components.dwHostNameLength == 0)
        goto cleanup;

    scheme = (WCHAR *)malloc(((size_t)components.dwSchemeLength + 1) * sizeof(WCHAR));
    host = (WCHAR *)malloc(((size_t)components.dwHostNameLength + 1) * sizeof(WCHAR));
    path = (WCHAR *)malloc(((size_t)components.dwUrlPathLength + 1) * sizeof(WCHAR));
    extra = (WCHAR *)malloc(((size_t)components.dwExtraInfoLength + 1) * sizeof(WCHAR));
    if (scheme == NULL || host == NULL || path == NULL || extra == NULL)
        goto cleanup;

    ZeroMemory(&components, sizeof(components));
    components.dwStructLength = sizeof(components);
    components.lpszScheme = scheme;
    components.dwSchemeLength = (DWORD)(wcslen(L"") + 1);
    components.lpszHostName = host;
    components.dwHostNameLength = (DWORD)(components.dwHostNameLength);
    components.lpszUrlPath = path;
    components.dwUrlPathLength = (DWORD)(components.dwUrlPathLength);
    components.lpszExtraInfo = extra;
    components.dwExtraInfoLength = (DWORD)(components.dwExtraInfoLength);

    {
        URL_COMPONENTS sizes;
        DWORD scheme_capacity;
        DWORD host_capacity;
        DWORD path_capacity;
        DWORD extra_capacity;

        ZeroMemory(&sizes, sizeof(sizes));
        sizes.dwStructLength = sizeof(sizes);
        if (!WinHttpCrackUrl(wide_endpoint, 0, 0, &sizes))
            goto cleanup;

        scheme_capacity = sizes.dwSchemeLength + 1;
        host_capacity = sizes.dwHostNameLength + 1;
        path_capacity = sizes.dwUrlPathLength + 1;
        extra_capacity = sizes.dwExtraInfoLength + 1;

        components.dwSchemeLength = scheme_capacity;
        components.dwHostNameLength = host_capacity;
        components.dwUrlPathLength = path_capacity;
        components.dwExtraInfoLength = extra_capacity;
        if (!WinHttpCrackUrl(wide_endpoint, 0, 0, &components))
            goto cleanup;

        components.lpszScheme[components.dwSchemeLength] = L'\0';
        components.lpszHostName[components.dwHostNameLength] = L'\0';
        components.lpszUrlPath[components.dwUrlPathLength] = L'\0';
        components.lpszExtraInfo[components.dwExtraInfoLength] = L'\0';
    }

    if (_wcsicmp(scheme, L"https") == 0)
        request_flags = WINHTTP_FLAG_SECURE;
    else if (_wcsicmp(scheme, L"http") != 0)
        goto cleanup;

    path_length = wcslen(path);
    extra_length = wcslen(extra);
    target_length = path_length + extra_length;
    if (target_length > (SIZE_MAX / sizeof(WCHAR)) - 1)
        goto cleanup;

    target = (WCHAR *)malloc((target_length + 2) * sizeof(WCHAR));
    if (target == NULL)
        goto cleanup;

    if (path_length != 0)
        memcpy(target, path, path_length * sizeof(WCHAR));
    if (extra_length != 0)
        memcpy(target + path_length, extra, extra_length * sizeof(WCHAR));
    target[target_length] = L'\0';

    for (fragment_offset = 0; fragment_offset < target_length; ++fragment_offset) {
        if (target[fragment_offset] == L'#') {
            target[fragment_offset] = L'\0';
            break;
        }
    }

    if (target[0] == L'\0') {
        target[0] = L'/';
        target[1] = L'\0';
    }

    {
        size_t length = strlen(token_json);
        if (length > MAXDWORD)
            goto cleanup;
        body_length = (DWORD)length;
    }

    session = WinHttpOpen(L"transmit_token/1.0",
                          WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS,
                          0);
    if (session == NULL)
        goto cleanup;

    connection = WinHttpConnect(session, host, components.nPort, 0);
    if (connection == NULL)
        goto cleanup;

    request = WinHttpOpenRequest(connection, L"POST", target,
                                 NULL, WINHTTP_NO_REFERER,
                                 WINHTTP_DEFAULT_ACCEPT_TYPES,
                                 request_flags);
    if (request == NULL)
        goto cleanup;

    if (!WinHttpSendRequest(request,
                            L"Content-Type: application/json\r\n",
                            (DWORD)-1L,
                            (LPVOID)token_json,
                            body_length,
                            body_length,
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
    free(target);
    free(extra);
    free(path);
    free(host);
    free(scheme);
    free(wide_endpoint);
    return result;
}