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
#include <stdlib.h>
#include <string.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    int result = -1;
    size_t endpoint_length;
    size_t body_length;
    char *scheme = NULL;
    char *host = NULL;
    char *url_path = NULL;
    char *extra_info = NULL;
    char *request_object = NULL;
    HINTERNET internet = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    URL_COMPONENTSA components;
    DWORD component_capacity;
    DWORD request_flags = 0;
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    BYTE response_buffer[4096];
    DWORD bytes_read;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    endpoint_length = strlen(endpoint);
    body_length = strlen(token_json);
    if (endpoint_length == 0 || endpoint_length >= MAXDWORD ||
        body_length > MAXDWORD)
        return -1;

    component_capacity = (DWORD)(endpoint_length + 1);
    scheme = (char *)malloc(endpoint_length + 1);
    host = (char *)malloc(endpoint_length + 1);
    url_path = (char *)malloc(endpoint_length + 1);
    extra_info = (char *)malloc(endpoint_length + 1);
    if (scheme == NULL || host == NULL || url_path == NULL || extra_info == NULL)
        goto cleanup;

    memset(&components, 0, sizeof(components));
    components.dwStructSize = sizeof(components);
    components.lpszScheme = scheme;
    components.dwSchemeLength = component_capacity;
    components.lpszHostName = host;
    components.dwHostNameLength = component_capacity;
    components.lpszUrlPath = url_path;
    components.dwUrlPathLength = component_capacity;
    components.lpszExtraInfo = extra_info;
    components.dwExtraInfoLength = component_capacity;

    if (!InternetCrackUrlA(endpoint, (DWORD)endpoint_length, 0, &components))
        goto cleanup;

    if (components.dwSchemeLength >= component_capacity ||
        components.dwHostNameLength >= component_capacity ||
        components.dwUrlPathLength >= component_capacity ||
        components.dwExtraInfoLength >= component_capacity)
        goto cleanup;

    scheme[components.dwSchemeLength] = '\0';
    host[components.dwHostNameLength] = '\0';
    url_path[components.dwUrlPathLength] = '\0';
    extra_info[components.dwExtraInfoLength] = '\0';

    if (components.dwHostNameLength == 0)
        goto cleanup;

    if (components.nScheme == INTERNET_SCHEME_HTTPS)
        request_flags |= INTERNET_FLAG_SECURE;
    else if (components.nScheme != INTERNET_SCHEME_HTTP)
        goto cleanup;

    {
        size_t path_length = components.dwUrlPathLength;
        size_t extra_length = components.dwExtraInfoLength;
        size_t object_length = (path_length == 0 ? 1 : path_length) + extra_length;

        request_object = (char *)malloc(object_length + 1);
        if (request_object == NULL)
            goto cleanup;

        if (path_length == 0) {
            request_object[0] = '/';
            path_length = 1;
        } else {
            memcpy(request_object, url_path, path_length);
        }

        if (extra_length != 0)
            memcpy(request_object + path_length, extra_info, extra_length);
        request_object[object_length] = '\0';
    }

    internet = InternetOpenA("transmit_token", INTERNET_OPEN_TYPE_PRECONFIG,
                              NULL, NULL, 0);
    if (internet == NULL)
        goto cleanup;

    connection = InternetConnectA(internet, host, components.nPort,
                                  NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (connection == NULL)
        goto cleanup;

    request = HttpOpenRequestA(connection, "POST", request_object, NULL, NULL,
                               NULL, request_flags, 0);
    if (request == NULL)
        goto cleanup;

    if (!HttpSendRequestA(request, "Content-Type: application/json\r\n",
                          (DWORD)-1, (LPVOID)token_json, (DWORD)body_length))
        goto cleanup;

    for (;;) {
        bytes_read = 0;
        if (!InternetReadFile(request, response_buffer,
                              (DWORD)sizeof(response_buffer), &bytes_read))
            goto cleanup;
        if (bytes_read == 0)
            break;
    }

    if (!HttpQueryInfoA(request,
                        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &status_code, &status_size, NULL))
        goto cleanup;

    if (status_code == 200)
        result = 0;

cleanup:
    if (request != NULL)
        InternetCloseHandle(request);
    if (connection != NULL)
        InternetCloseHandle(connection);
    if (internet != NULL)
        InternetCloseHandle(internet);

    free(request_object);
    free(extra_info);
    free(url_path);
    free(host);
    free(scheme);

    return result;
}