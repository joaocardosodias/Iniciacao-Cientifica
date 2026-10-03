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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    size_t endpoint_length;
    size_t body_length;
    size_t component_capacity;
    size_t path_length;
    size_t extra_length;
    size_t request_target_length;
    char *host = NULL;
    char *url_path = NULL;
    char *extra_info = NULL;
    char *request_target = NULL;
    URL_COMPONENTSA components;
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    DWORD request_flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    DWORD bytes_read;
    DWORD status_code = 0;
    DWORD status_code_size = sizeof(status_code);
    char response_buffer[4096];
    BOOL ok;
    int result = -1;

    if (endpoint == NULL || token_json == NULL) {
        return -1;
    }

    endpoint_length = strlen(endpoint);
    body_length = strlen(token_json);
    if (endpoint_length == 0 ||
        endpoint_length >= (size_t)MAXDWORD ||
        body_length > (size_t)MAXDWORD) {
        return -1;
    }

    component_capacity = endpoint_length + 1;
    host = (char *)malloc(component_capacity);
    url_path = (char *)malloc(component_capacity);
    extra_info = (char *)malloc(component_capacity);
    if (host == NULL || url_path == NULL || extra_info == NULL) {
        goto cleanup;
    }

    memset(&components, 0, sizeof(components));
    components.dwStructSize = sizeof(components);
    components.lpszHostName = host;
    components.dwHostNameLength = (DWORD)component_capacity;
    components.lpszUrlPath = url_path;
    components.dwUrlPathLength = (DWORD)component_capacity;
    components.lpszExtraInfo = extra_info;
    components.dwExtraInfoLength = (DWORD)component_capacity;

    if (!InternetCrackUrlA(endpoint, 0, 0, &components) ||
        components.dwHostNameLength == 0 ||
        (components.nScheme != INTERNET_SCHEME_HTTP &&
         components.nScheme != INTERNET_SCHEME_HTTPS)) {
        goto cleanup;
    }

    host[components.dwHostNameLength] = '\0';
    path_length = components.dwUrlPathLength;
    extra_length = components.dwExtraInfoLength;

    if (path_length > component_capacity - 1 ||
        extra_length > component_capacity - 1 ||
        path_length > (size_t)-1 - extra_length) {
        goto cleanup;
    }

    request_target_length = path_length + extra_length;
    if (request_target_length == 0) {
        request_target = (char *)malloc(2);
        if (request_target == NULL) {
            goto cleanup;
        }
        request_target[0] = '/';
        request_target[1] = '\0';
    } else {
        if (request_target_length == (size_t)-1) {
            goto cleanup;
        }
        request_target = (char *)malloc(request_target_length + 1);
        if (request_target == NULL) {
            goto cleanup;
        }
        memcpy(request_target, url_path, path_length);
        memcpy(request_target + path_length, extra_info, extra_length);
        request_target[request_target_length] = '\0';
    }

    if (components.nPort == 0) {
        components.nPort = components.nScheme == INTERNET_SCHEME_HTTPS
                               ? INTERNET_DEFAULT_HTTPS_PORT
                               : INTERNET_DEFAULT_HTTP_PORT;
    }

    if (components.nScheme == INTERNET_SCHEME_HTTPS) {
        request_flags |= INTERNET_FLAG_SECURE;
    }

    session = InternetOpenA("transmit_token", INTERNET_OPEN_TYPE_PRECONFIG,
                            NULL, NULL, 0);
    if (session == NULL) {
        goto cleanup;
    }

    connection = InternetConnectA(session, host, components.nPort, NULL, NULL,
                                  INTERNET_SERVICE_HTTP, 0, 0);
    if (connection == NULL) {
        goto cleanup;
    }

    request = HttpOpenRequestA(connection, "POST", request_target, NULL, NULL,
                               NULL, request_flags, 0);
    if (request == NULL) {
        goto cleanup;
    }

    ok = HttpSendRequestA(request, "Content-Type: application/json\r\n",
                          (DWORD)-1, (LPVOID)token_json, (DWORD)body_length);
    if (!ok) {
        goto cleanup;
    }

    do {
        bytes_read = 0;
        if (!InternetReadFile(request, response_buffer,
                              (DWORD)sizeof(response_buffer), &bytes_read)) {
            goto cleanup;
        }
    } while (bytes_read != 0);

    if (!HttpQueryInfoA(request,
                        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &status_code, &status_code_size, NULL)) {
        goto cleanup;
    }

    if (status_code == 200) {
        result = 0;
    }

cleanup:
    if (request != NULL) {
        InternetCloseHandle(request);
    }
    if (connection != NULL) {
        InternetCloseHandle(connection);
    }
    if (session != NULL) {
        InternetCloseHandle(session);
    }
    free(request_target);
    free(extra_info);
    free(url_path);
    free(host);
    return result;
}