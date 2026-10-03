#include <windows.h>
#include <wininet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    char *scheme = NULL;
    char *host = NULL;
    char *url_path = NULL;
    char *extra_info = NULL;
    char *object_name = NULL;
    int result = -1;

    if (endpoint == NULL || token_json == NULL) {
        return -1;
    }

    size_t endpoint_length = strlen(endpoint);
    size_t body_length = strlen(token_json);
    if (endpoint_length == 0 ||
        endpoint_length >= (size_t)MAXDWORD ||
        body_length > (size_t)MAXDWORD) {
        return -1;
    }

    size_t component_capacity = endpoint_length + 1;
    scheme = (char *)calloc(component_capacity, 1);
    host = (char *)calloc(component_capacity, 1);
    url_path = (char *)calloc(component_capacity, 1);
    extra_info = (char *)calloc(component_capacity, 1);
    if (scheme == NULL || host == NULL || url_path == NULL ||
        extra_info == NULL) {
        goto cleanup;
    }

    URL_COMPONENTSA components;
    memset(&components, 0, sizeof(components));
    components.dwStructSize = sizeof(components);
    components.lpszScheme = scheme;
    components.dwSchemeLength = (DWORD)component_capacity;
    components.lpszHostName = host;
    components.dwHostNameLength = (DWORD)component_capacity;
    components.lpszUrlPath = url_path;
    components.dwUrlPathLength = (DWORD)component_capacity;
    components.lpszExtraInfo = extra_info;
    components.dwExtraInfoLength = (DWORD)component_capacity;

    if (!InternetCrackUrlA(endpoint, (DWORD)endpoint_length, 0, &components) ||
        components.dwSchemeLength == 0 ||
        components.dwHostNameLength == 0 ||
        components.dwSchemeLength >= component_capacity ||
        components.dwHostNameLength >= component_capacity ||
        components.dwUrlPathLength >= component_capacity ||
        components.dwExtraInfoLength >= component_capacity ||
        (components.nScheme != INTERNET_SCHEME_HTTP &&
         components.nScheme != INTERNET_SCHEME_HTTPS)) {
        goto cleanup;
    }

    scheme[components.dwSchemeLength] = '\0';
    host[components.dwHostNameLength] = '\0';
    url_path[components.dwUrlPathLength] = '\0';
    extra_info[components.dwExtraInfoLength] = '\0';

    size_t path_length = components.dwUrlPathLength;
    size_t extra_length = components.dwExtraInfoLength;
    char *fragment = memchr(extra_info, '#', extra_length);
    if (fragment != NULL) {
        extra_length = (size_t)(fragment - extra_info);
    }

    if (path_length > SIZE_MAX - extra_length - 2u) {
        goto cleanup;
    }
    size_t object_capacity = path_length + extra_length + 2u;
    object_name = (char *)malloc(object_capacity);
    if (object_name == NULL) {
        goto cleanup;
    }

    size_t object_length = 0;
    if (path_length == 0) {
        object_name[object_length++] = '/';
    } else {
        memcpy(object_name, url_path, path_length);
        object_length = path_length;
    }
    if (extra_length != 0) {
        memcpy(object_name + object_length, extra_info, extra_length);
        object_length += extra_length;
    }
    object_name[object_length] = '\0';

    session = InternetOpenA("transmit_token",
                            INTERNET_OPEN_TYPE_PRECONFIG,
                            NULL,
                            NULL,
                            0);
    if (session == NULL) {
        goto cleanup;
    }

    connection = InternetConnectA(session,
                                  host,
                                  components.nPort,
                                  NULL,
                                  NULL,
                                  INTERNET_SERVICE_HTTP,
                                  0,
                                  0);
    if (connection == NULL) {
        goto cleanup;
    }

    DWORD request_flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (components.nScheme == INTERNET_SCHEME_HTTPS) {
        request_flags |= INTERNET_FLAG_SECURE;
    }

    request = HttpOpenRequestA(connection,
                               "POST",
                               object_name,
                               "HTTP/1.1",
                               NULL,
                               NULL,
                               request_flags,
                               0);
    if (request == NULL) {
        goto cleanup;
    }

    static const char headers[] = "Content-Type: application/json\r\n";
    if (!HttpSendRequestA(request,
                          headers,
                          (DWORD)-1,
                          (LPVOID)token_json,
                          (DWORD)body_length)) {
        goto cleanup;
    }

    {
        BYTE response_buffer[4096];
        DWORD bytes_read = 0;
        for (;;) {
            if (!InternetReadFile(request,
                                  response_buffer,
                                  sizeof(response_buffer),
                                  &bytes_read)) {
                goto cleanup;
            }
            if (bytes_read == 0) {
                break;
            }
        }
    }

    {
        DWORD status_code = 0;
        DWORD status_size = sizeof(status_code);
        if (!HttpQueryInfoA(request,
                            HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
                            &status_code,
                            &status_size,
                            NULL)) {
            goto cleanup;
        }
        if (status_code == 200) {
            result = 0;
        }
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
    free(object_name);
    free(extra_info);
    free(url_path);
    free(host);
    free(scheme);
    return result;
}