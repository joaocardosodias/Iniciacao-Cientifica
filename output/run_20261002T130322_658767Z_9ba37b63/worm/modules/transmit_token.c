#include <windows.h>
#include <wininet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    URL_COMPONENTSA url;
    HINTERNET internet = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    char *host = NULL;
    char *object_name = NULL;
    size_t host_length;
    size_t path_length;
    size_t extra_length;
    size_t object_length;
    size_t body_length;
    INTERNET_PORT port;
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    DWORD status = 0;
    DWORD status_size = sizeof(status);
    DWORD bytes_read;
    char response_buffer[4096];
    int result = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    ZeroMemory(&url, sizeof(url));
    url.dwStructSize = sizeof(url);
    if (!InternetCrackUrlA(endpoint, 0, 0, &url) ||
        url.lpszHostName == NULL || url.dwHostNameLength == 0)
        return -1;

    if (url.nScheme != INTERNET_SCHEME_HTTP &&
        url.nScheme != INTERNET_SCHEME_HTTPS)
        return -1;

    host_length = url.dwHostNameLength;
    path_length = url.lpszUrlPath != NULL ? url.dwUrlPathLength : 0;
    extra_length = url.lpszExtraInfo != NULL ? url.dwExtraInfoLength : 0;

    if (host_length == SIZE_MAX ||
        path_length > SIZE_MAX - extra_length ||
        path_length + extra_length > SIZE_MAX - 2)
        return -1;

    host = (char *)malloc(host_length + 1);
    if (host == NULL)
        goto cleanup;
    memcpy(host, url.lpszHostName, host_length);
    host[host_length] = '\0';

    object_length = (path_length != 0 ? path_length : 1) + extra_length;
    object_name = (char *)malloc(object_length + 1);
    if (object_name == NULL)
        goto cleanup;

    if (path_length != 0)
        memcpy(object_name, url.lpszUrlPath, path_length);
    else
        object_name[0] = '/';
    if (extra_length != 0)
        memcpy(object_name + (path_length != 0 ? path_length : 1),
               url.lpszExtraInfo, extra_length);
    object_name[object_length] = '\0';

    body_length = strlen(token_json);
    if (body_length > MAXDWORD)
        goto cleanup;

    port = url.nPort;
    if (port == 0)
        port = url.nScheme == INTERNET_SCHEME_HTTPS
                   ? INTERNET_DEFAULT_HTTPS_PORT
                   : INTERNET_DEFAULT_HTTP_PORT;

    if (url.nScheme == INTERNET_SCHEME_HTTPS)
        flags |= INTERNET_FLAG_SECURE;

    internet = InternetOpenA("transmit_token", INTERNET_OPEN_TYPE_PRECONFIG,
                             NULL, NULL, 0);
    if (internet == NULL)
        goto cleanup;

    connection = InternetConnectA(internet, host, port, NULL, NULL,
                                  INTERNET_SERVICE_HTTP, 0, 0);
    if (connection == NULL)
        goto cleanup;

    request = HttpOpenRequestA(connection, "POST", object_name, NULL, NULL,
                               NULL, flags, 0);
    if (request == NULL)
        goto cleanup;

    if (!HttpSendRequestA(request, "Content-Type: application/json\r\n",
                          (DWORD)-1, (LPVOID)token_json, (DWORD)body_length))
        goto cleanup;

    if (!HttpQueryInfoA(request, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &status, &status_size, NULL))
        goto cleanup;

    for (;;) {
        bytes_read = 0;
        if (!InternetReadFile(request, response_buffer,
                              (DWORD)sizeof(response_buffer), &bytes_read))
            goto cleanup;
        if (bytes_read == 0)
            break;
    }

    if (status == 200)
        result = 0;

cleanup:
    if (request != NULL)
        InternetCloseHandle(request);
    if (connection != NULL)
        InternetCloseHandle(connection);
    if (internet != NULL)
        InternetCloseHandle(internet);
    free(object_name);
    free(host);
    return result;
}