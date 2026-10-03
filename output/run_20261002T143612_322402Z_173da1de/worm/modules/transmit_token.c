#include <windows.h>
#include <wininet.h>
#include <stdlib.h>
#include <string.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    char *host = NULL;
    char *scheme = NULL;
    char *path = NULL;
    char *extra = NULL;
    char *object_name = NULL;
    int result = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    size_t endpoint_length = strlen(endpoint);
    size_t token_length = strlen(token_json);
    if (endpoint_length == 0 ||
        endpoint_length >= (size_t)0xFFFFFFFFUL ||
        token_length > (size_t)0xFFFFFFFFUL)
        return -1;

    size_t buffer_size = endpoint_length + 1;
    host = (char *)malloc(buffer_size);
    scheme = (char *)malloc(buffer_size);
    path = (char *)malloc(buffer_size);
    extra = (char *)malloc(buffer_size);
    if (host == NULL || scheme == NULL || path == NULL || extra == NULL)
        goto cleanup;

    URL_COMPONENTSA components;
    ZeroMemory(&components, sizeof(components));
    components.dwStructSize = sizeof(components);
    components.lpszScheme = scheme;
    components.dwSchemeLength = (DWORD)buffer_size;
    components.lpszHostName = host;
    components.dwHostNameLength = (DWORD)buffer_size;
    components.lpszUrlPath = path;
    components.dwUrlPathLength = (DWORD)buffer_size;
    components.lpszExtraInfo = extra;
    components.dwExtraInfoLength = (DWORD)buffer_size;

    if (!InternetCrackUrlA(endpoint, (DWORD)endpoint_length, 0, &components) ||
        components.dwHostNameLength == 0 ||
        (components.nScheme != INTERNET_SCHEME_HTTP &&
         components.nScheme != INTERNET_SCHEME_HTTPS))
        goto cleanup;

    host[components.dwHostNameLength] = '\0';
    path[components.dwUrlPathLength] = '\0';
    extra[components.dwExtraInfoLength] = '\0';

    size_t path_length = components.dwUrlPathLength;
    size_t extra_length = components.dwExtraInfoLength;
    if (path_length == 0)
        path_length = 1;
    if (path_length > (size_t)-1 - extra_length - 1)
        goto cleanup;

    object_name = (char *)malloc(path_length + extra_length + 1);
    if (object_name == NULL)
        goto cleanup;

    if (components.dwUrlPathLength == 0)
        object_name[0] = '/';
    else
        memcpy(object_name, path, path_length);
    memcpy(object_name + path_length, extra, extra_length);
    object_name[path_length + extra_length] = '\0';

    session = InternetOpenA("transmit_token", INTERNET_OPEN_TYPE_PRECONFIG,
                            NULL, NULL, 0);
    if (session == NULL)
        goto cleanup;

    connection = InternetConnectA(session, host, components.nPort, NULL, NULL,
                                  INTERNET_SERVICE_HTTP, 0, 0);
    if (connection == NULL)
        goto cleanup;

    DWORD request_flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (components.nScheme == INTERNET_SCHEME_HTTPS)
        request_flags |= INTERNET_FLAG_SECURE;

    request = HttpOpenRequestA(connection, "POST", object_name, NULL, NULL,
                               NULL, request_flags, 0);
    if (request == NULL)
        goto cleanup;

    static const char headers[] = "Content-Type: application/json\r\n";
    if (!HttpSendRequestA(request, headers, (DWORD)(sizeof(headers) - 1),
                          (LPVOID)token_json, (DWORD)token_length))
        goto cleanup;

    {
        char response_buffer[4096];
        DWORD bytes_read = 0;
        do {
            if (!InternetReadFile(request, response_buffer,
                                  (DWORD)sizeof(response_buffer), &bytes_read))
                goto cleanup;
        } while (bytes_read != 0);
    }

    {
        DWORD status_code = 0;
        DWORD status_size = sizeof(status_code);
        if (HttpQueryInfoA(request,
                           HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                           &status_code, &status_size, NULL) &&
            status_code == 200)
            result = 0;
    }

cleanup:
    if (request != NULL)
        InternetCloseHandle(request);
    if (connection != NULL)
        InternetCloseHandle(connection);
    if (session != NULL)
        InternetCloseHandle(session);
    free(object_name);
    free(extra);
    free(path);
    free(scheme);
    free(host);
    return result;
}