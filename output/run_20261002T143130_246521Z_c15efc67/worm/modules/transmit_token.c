#include <windows.h>
#include <wininet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    URL_COMPONENTSA components;
    URL_COMPONENTSA parsed;
    char *host = NULL;
    char *url_path = NULL;
    char *extra_info = NULL;
    char *request_path = NULL;
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    INTERNET_PORT port;
    DWORD host_length;
    DWORD path_length;
    DWORD extra_length;
    DWORD status_code = 0;
    DWORD status_length = sizeof(status_code);
    DWORD bytes_read;
    DWORD body_length;
    size_t request_path_length;
    size_t token_length;
    DWORD request_flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    int is_https;
    int result = -1;
    char response_buffer[4096];

    if (endpoint == NULL || token_json == NULL)
        return -1;

    token_length = strlen(token_json);
    if (token_length > 0xFFFFFFFFUL)
        return -1;
    body_length = (DWORD)token_length;

    memset(&components, 0, sizeof(components));
    components.dwStructSize = sizeof(components);
    if (!InternetCrackUrlA(endpoint, 0, 0, &components))
        return -1;

    is_https = components.nScheme == INTERNET_SCHEME_HTTPS;
    if (!is_https && components.nScheme != INTERNET_SCHEME_HTTP)
        return -1;

    host_length = components.dwHostNameLength;
    path_length = components.dwUrlPathLength;
    extra_length = components.dwExtraInfoLength;
    port = components.nPort;

    if (host_length == 0 || host_length == 0xFFFFFFFFUL ||
        path_length == 0xFFFFFFFFUL || extra_length == 0xFFFFFFFFUL)
        return -1;

    host = (char *)malloc((size_t)host_length + 1);
    url_path = (char *)malloc((size_t)path_length + 1);
    extra_info = (char *)malloc((size_t)extra_length + 1);
    if (host == NULL || url_path == NULL || extra_info == NULL)
        goto cleanup;

    memset(&parsed, 0, sizeof(parsed));
    parsed.dwStructSize = sizeof(parsed);
    parsed.lpszHostName = host;
    parsed.dwHostNameLength = host_length + 1;
    parsed.lpszUrlPath = url_path;
    parsed.dwUrlPathLength = path_length + 1;
    parsed.lpszExtraInfo = extra_info;
    parsed.dwExtraInfoLength = extra_length + 1;

    if (!InternetCrackUrlA(endpoint, 0, 0, &parsed))
        goto cleanup;

    host[parsed.dwHostNameLength] = '\0';
    url_path[parsed.dwUrlPathLength] = '\0';
    extra_info[parsed.dwExtraInfoLength] = '\0';

    if ((size_t)parsed.dwUrlPathLength > SIZE_MAX - (size_t)parsed.dwExtraInfoLength - 2)
        goto cleanup;
    request_path_length = (size_t)parsed.dwUrlPathLength +
                          (size_t)parsed.dwExtraInfoLength;
    request_path = (char *)malloc(request_path_length + 2);
    if (request_path == NULL)
        goto cleanup;

    if (parsed.dwUrlPathLength == 0 || url_path[0] != '/') {
        request_path[0] = '/';
        if (parsed.dwUrlPathLength != 0)
            memcpy(request_path + 1, url_path, parsed.dwUrlPathLength);
        memcpy(request_path + 1 + parsed.dwUrlPathLength, extra_info,
               parsed.dwExtraInfoLength);
        request_path_length++;
    } else {
        memcpy(request_path, url_path, parsed.dwUrlPathLength);
        memcpy(request_path + parsed.dwUrlPathLength, extra_info,
               parsed.dwExtraInfoLength);
    }
    request_path[request_path_length] = '\0';

    {
        char *fragment = strchr(request_path, '#');
        if (fragment != NULL)
            *fragment = '\0';
    }

    session = InternetOpenA("transmit_token", INTERNET_OPEN_TYPE_PRECONFIG,
                            NULL, NULL, 0);
    if (session == NULL)
        goto cleanup;

    connection = InternetConnectA(session, host, port, NULL, NULL,
                                  INTERNET_SERVICE_HTTP, 0, 0);
    if (connection == NULL)
        goto cleanup;

    if (is_https)
        request_flags |= INTERNET_FLAG_SECURE;

    request = HttpOpenRequestA(connection, "POST", request_path, NULL, NULL,
                               NULL, request_flags, 0);
    if (request == NULL)
        goto cleanup;

    if (!HttpSendRequestA(request, "Content-Type: application/json\r\n", -1L,
                          (LPVOID)token_json, body_length))
        goto cleanup;

    if (!HttpQueryInfoA(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &status_code, &status_length, NULL))
        goto cleanup;

    for (;;) {
        bytes_read = 0;
        if (!InternetReadFile(request, response_buffer,
                              (DWORD)sizeof(response_buffer), &bytes_read))
            goto cleanup;
        if (bytes_read == 0)
            break;
    }

    if (status_code == 200)
        result = 0;

cleanup:
    if (request != NULL)
        InternetCloseHandle(request);
    if (connection != NULL)
        InternetCloseHandle(connection);
    if (session != NULL)
        InternetCloseHandle(session);
    free(request_path);
    free(extra_info);
    free(url_path);
    free(host);
    return result;
}