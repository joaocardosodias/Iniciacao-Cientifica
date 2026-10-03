#include <windows.h>
#include <wininet.h>
#include <stdlib.h>
#include <string.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    HINTERNET internet = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    char *component_storage = NULL;
    char *scheme;
    char *host;
    char *path;
    char *extra;
    char *user;
    char *password;
    char *object_name = NULL;
    size_t endpoint_length;
    size_t token_length;
    size_t component_capacity;
    size_t object_length;
    URL_COMPONENTSA components;
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    DWORD request_flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    BOOL success = FALSE;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    endpoint_length = strlen(endpoint);
    token_length = strlen(token_json);
    if (endpoint_length == 0 || endpoint_length >= (size_t)MAXDWORD ||
        token_length > (size_t)MAXDWORD)
        return -1;

    component_capacity = endpoint_length + 1;
    if (component_capacity > (size_t)-1 / 6)
        return -1;

    component_storage = (char *)malloc(component_capacity * 6);
    if (component_storage == NULL)
        return -1;

    scheme = component_storage;
    host = scheme + component_capacity;
    path = host + component_capacity;
    extra = path + component_capacity;
    user = extra + component_capacity;
    password = user + component_capacity;

    memset(&components, 0, sizeof(components));
    components.dwStructSize = sizeof(components);
    components.lpszScheme = scheme;
    components.dwSchemeLength = (DWORD)component_capacity;
    components.lpszHostName = host;
    components.dwHostNameLength = (DWORD)component_capacity;
    components.lpszUrlPath = path;
    components.dwUrlPathLength = (DWORD)component_capacity;
    components.lpszExtraInfo = extra;
    components.dwExtraInfoLength = (DWORD)component_capacity;
    components.lpszUserName = user;
    components.dwUserNameLength = (DWORD)component_capacity;
    components.lpszPassword = password;
    components.dwPasswordLength = (DWORD)component_capacity;

    if (!InternetCrackUrlA(endpoint, (DWORD)endpoint_length, 0, &components))
        goto cleanup;

    if (components.dwHostNameLength == 0 ||
        components.dwHostNameLength >= component_capacity ||
        components.dwUrlPathLength >= component_capacity ||
        components.dwExtraInfoLength >= component_capacity)
        goto cleanup;

    scheme[components.dwSchemeLength < component_capacity
               ? components.dwSchemeLength
               : component_capacity - 1] = '\0';
    host[components.dwHostNameLength] = '\0';
    path[components.dwUrlPathLength] = '\0';
    extra[components.dwExtraInfoLength] = '\0';

    if (components.nScheme == INTERNET_SCHEME_HTTPS)
        request_flags |= INTERNET_FLAG_SECURE;
    else if (components.nScheme != INTERNET_SCHEME_HTTP)
        goto cleanup;

    object_length = components.dwUrlPathLength + components.dwExtraInfoLength;
    if (components.dwUrlPathLength == 0)
        object_length++;

    if (object_length == (size_t)-1)
        goto cleanup;

    object_name = (char *)malloc(object_length + 1);
    if (object_name == NULL)
        goto cleanup;

    if (components.dwUrlPathLength == 0) {
        object_name[0] = '/';
        if (components.dwExtraInfoLength != 0)
            memcpy(object_name + 1, extra, components.dwExtraInfoLength);
    } else {
        memcpy(object_name, path, components.dwUrlPathLength);
        if (components.dwExtraInfoLength != 0)
            memcpy(object_name + components.dwUrlPathLength, extra,
                   components.dwExtraInfoLength);
    }
    object_name[object_length] = '\0';

    internet = InternetOpenA("transmit_token", INTERNET_OPEN_TYPE_PRECONFIG,
                             NULL, NULL, 0);
    if (internet == NULL)
        goto cleanup;

    connection = InternetConnectA(internet, host, components.nPort,
                                  NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (connection == NULL)
        goto cleanup;

    request = HttpOpenRequestA(connection, "POST", object_name, NULL, NULL,
                               NULL, request_flags, 0);
    if (request == NULL)
        goto cleanup;

    if (!HttpSendRequestA(request, "Content-Type: application/json\r\n",
                          (DWORD)(sizeof("Content-Type: application/json\r\n") - 1),
                          (LPVOID)token_json, (DWORD)token_length))
        goto cleanup;

    if (!HttpQueryInfoA(request,
                        HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                        &status_code, &status_size, NULL))
        goto cleanup;

    {
        char buffer[4096];
        DWORD bytes_read;

        for (;;) {
            if (!InternetReadFile(request, buffer, sizeof(buffer), &bytes_read))
                goto cleanup;
            if (bytes_read == 0)
                break;
        }
    }

    success = (status_code == 200);

cleanup:
    if (request != NULL)
        InternetCloseHandle(request);
    if (connection != NULL)
        InternetCloseHandle(connection);
    if (internet != NULL)
        InternetCloseHandle(internet);
    free(object_name);
    free(component_storage);

    return success ? 0 : -1;
}