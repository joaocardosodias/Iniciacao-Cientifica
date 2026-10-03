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
#include <wininet.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    size_t url_len;
    size_t body_len;
    DWORD component_capacity;
    char *scheme = NULL;
    char *host = NULL;
    char *path = NULL;
    char *extra = NULL;
    char *request_path = NULL;
    URL_COMPONENTSA components;
    HINTERNET internet = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    INTERNET_PORT port;
    DWORD request_flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    DWORD status = 0;
    DWORD status_len = sizeof(status);
    DWORD bytes_read;
    char response_buffer[4096];
    const char *headers = "Content-Type: application/json\r\n";
    size_t path_len;
    size_t extra_len;
    int result = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    url_len = strlen(endpoint);
    body_len = strlen(token_json);
    if (url_len == 0 || url_len >= (size_t)ULONG_MAX ||
        body_len > (size_t)ULONG_MAX)
        return -1;

    component_capacity = (DWORD)(url_len + 1);
    scheme = (char *)malloc((size_t)component_capacity);
    host = (char *)malloc((size_t)component_capacity);
    path = (char *)malloc((size_t)component_capacity);
    extra = (char *)malloc((size_t)component_capacity);
    if (scheme == NULL || host == NULL || path == NULL || extra == NULL)
        goto cleanup;

    memset(&components, 0, sizeof(components));
    components.dwStructSize = sizeof(components);
    components.lpszScheme = scheme;
    components.dwSchemeLength = component_capacity;
    components.lpszHostName = host;
    components.dwHostNameLength = component_capacity;
    components.lpszUrlPath = path;
    components.dwUrlPathLength = component_capacity;
    components.lpszExtraInfo = extra;
    components.dwExtraInfoLength = component_capacity;

    if (!InternetCrackUrlA(endpoint, (DWORD)url_len, 0, &components))
        goto cleanup;

    if (components.dwSchemeLength >= component_capacity ||
        components.dwHostNameLength >= component_capacity ||
        components.dwUrlPathLength >= component_capacity ||
        components.dwExtraInfoLength >= component_capacity)
        goto cleanup;

    scheme[components.dwSchemeLength] = '\0';
    host[components.dwHostNameLength] = '\0';
    path[components.dwUrlPathLength] = '\0';
    extra[components.dwExtraInfoLength] = '\0';

    if (components.dwHostNameLength == 0)
        goto cleanup;

    if (components.nScheme == INTERNET_SCHEME_HTTP) {
        port = components.nPort != 0 ? components.nPort : INTERNET_DEFAULT_HTTP_PORT;
    } else if (components.nScheme == INTERNET_SCHEME_HTTPS) {
        port = components.nPort != 0 ? components.nPort : INTERNET_DEFAULT_HTTPS_PORT;
        request_flags |= INTERNET_FLAG_SECURE;
    } else {
        goto cleanup;
    }

    path_len = components.dwUrlPathLength;
    extra_len = components.dwExtraInfoLength;
    if (path_len > SIZE_MAX - extra_len - 2)
        goto cleanup;

    request_path = (char *)malloc(path_len + extra_len + 2);
    if (request_path == NULL)
        goto cleanup;

    if (path_len == 0) {
        request_path[0] = '/';
        path_len = 1;
    } else {
        memcpy(request_path, path, path_len);
    }
    memcpy(request_path + path_len, extra, extra_len);
    request_path[path_len + extra_len] = '\0';

    internet = InternetOpenA("transmit_token", INTERNET_OPEN_TYPE_PRECONFIG,
                             NULL, NULL, 0);
    if (internet == NULL)
        goto cleanup;

    connection = InternetConnectA(internet, host, port, NULL, NULL,
                                  INTERNET_SERVICE_HTTP, 0, 0);
    if (connection == NULL)
        goto cleanup;

    request = HttpOpenRequestA(connection, "POST", request_path, "HTTP/1.1",
                               NULL, NULL, request_flags, 0);
    if (request == NULL)
        goto cleanup;

    if (!HttpSendRequestA(request, headers, (DWORD)-1L, (LPVOID)token_json,
                          (DWORD)body_len))
        goto cleanup;

    if (!HttpQueryInfoA(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &status, &status_len, NULL))
        goto cleanup;

    do {
        bytes_read = 0;
        if (!InternetReadFile(request, response_buffer,
                              (DWORD)sizeof(response_buffer), &bytes_read))
            goto cleanup;
    } while (bytes_read != 0);

    result = status == 200 ? 0 : -1;

cleanup:
    if (request != NULL)
        InternetCloseHandle(request);
    if (connection != NULL)
        InternetCloseHandle(connection);
    if (internet != NULL)
        InternetCloseHandle(internet);
    free(request_path);
    free(extra);
    free(path);
    free(host);
    free(scheme);
    return result;
}