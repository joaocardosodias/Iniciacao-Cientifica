#include <windows.h>
#include <winhttp.h>
#include <string.h>
#include <stdlib.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    size_t endpoint_length;
    size_t body_length;
    const char *authority;
    const char *authority_end;
    const char *host_start;
    const char *host_end;
    const char *port_start = NULL;
    const char *remainder;
    const char *fragment;
    size_t host_length;
    size_t target_length;
    char *host = NULL;
    char *target = NULL;
    INTERNET_PORT port;
    DWORD request_flags = 0;
    DWORD status_code = 0;
    DWORD status_size = sizeof(status_code);
    HINTERNET session = NULL;
    HINTERNET connection = NULL;
    HINTERNET request = NULL;
    int result = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    endpoint_length = strlen(endpoint);
    body_length = strlen(token_json);
    if (endpoint_length == 0 || endpoint_length > MAXDWORD ||
        body_length > MAXDWORD)
        return -1;

    if (_strnicmp(endpoint, "http://", 7) == 0) {
        authority = endpoint + 7;
        port = INTERNET_DEFAULT_HTTP_PORT;
    } else if (_strnicmp(endpoint, "https://", 8) == 0) {
        authority = endpoint + 8;
        port = INTERNET_DEFAULT_HTTPS_PORT;
        request_flags |= WINHTTP_FLAG_SECURE;
    } else {
        return -1;
    }

    authority_end = authority;
    while (*authority_end != '\0' && *authority_end != '/' &&
           *authority_end != '?' && *authority_end != '#')
        ++authority_end;
    if (authority_end == authority ||
        memchr(authority, '@', (size_t)(authority_end - authority)) != NULL)
        return -1;

    if (*authority == '[') {
        const char *closing_bracket = memchr(authority, ']', (size_t)(authority_end - authority));
        if (closing_bracket == NULL || closing_bracket == authority + 1)
            return -1;
        host_start = authority + 1;
        host_end = closing_bracket;
        if (closing_bracket + 1 < authority_end) {
            if (closing_bracket[1] != ':')
                return -1;
            port_start = closing_bracket + 2;
        }
    } else {
        const char *colon = NULL;
        const char *p;
        host_start = authority;
        host_end = authority_end;
        for (p = authority; p < authority_end; ++p) {
            if (*p == ':') {
                if (colon != NULL)
                    return -1;
                colon = p;
            }
        }
        if (colon != NULL) {
            host_end = colon;
            port_start = colon + 1;
        }
    }

    host_length = (size_t)(host_end - host_start);
    if (host_length == 0)
        return -1;

    if (port_start != NULL) {
        unsigned long parsed_port = 0;
        const char *p;
        if (port_start >= authority_end)
            return -1;
        for (p = port_start; p < authority_end; ++p) {
            if (*p < '0' || *p > '9')
                return -1;
            parsed_port = parsed_port * 10UL + (unsigned long)(*p - '0');
            if (parsed_port > 65535UL)
                return -1;
        }
        if (parsed_port == 0)
            return -1;
        port = (INTERNET_PORT)parsed_port;
    }

    host = (char *)malloc(host_length + 1);
    target = (char *)malloc(endpoint_length + 2);
    if (host == NULL || target == NULL)
        goto cleanup;

    memcpy(host, host_start, host_length);
    host[host_length] = '\0';

    remainder = authority_end;
    fragment = strchr(remainder, '#');
    target_length = fragment != NULL ? (size_t)(fragment - remainder) : strlen(remainder);
    if (target_length == 0 || *remainder == '#') {
        target[0] = '/';
        target[1] = '\0';
    } else if (*remainder == '/') {
        memcpy(target, remainder, target_length);
        target[target_length] = '\0';
    } else if (*remainder == '?') {
        target[0] = '/';
        memcpy(target + 1, remainder, target_length);
        target[target_length + 1] = '\0';
    } else {
        goto cleanup;
    }

    session = WinHttpOpenA("transmit_token", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                           WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (session == NULL)
        goto cleanup;

    connection = WinHttpConnectA(session, host, port, 0);
    if (connection == NULL)
        goto cleanup;

    request = WinHttpOpenRequestA(connection, "POST", target, NULL,
                                  WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                  request_flags);
    if (request == NULL)
        goto cleanup;

    if (!WinHttpSendRequestA(request, "Content-Type: application/json\r\n",
                             (DWORD)-1, (LPVOID)token_json, (DWORD)body_length,
                             (DWORD)body_length, 0))
        goto cleanup;

    if (!WinHttpReceiveResponse(request, NULL))
        goto cleanup;

    if (!WinHttpQueryHeaders(request,
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &status_code,
                             &status_size, WINHTTP_NO_HEADER_INDEX))
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
    free(host);
    return result;
}