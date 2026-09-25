#define _GNU_SOURCE
#include <ctype.h>
#include <curl/curl.h>
#include <curl/urlapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define TOKEN_FILE_PATH "/tmp/.session.token"
#define TOKEN_MAX_FILE_SIZE 8192U
#define TOKEN_MAX_VALUE_SIZE 4096U
#define HOSTNAME_MAX_SIZE 256U
#define URL_MAX_SIZE 4096U
#define RESPONSE_MAX_SIZE 16384U

typedef struct {
    const char *data;
    size_t length;
    size_t position;
} token_json_parser;

typedef struct {
    char *data;
    size_t length;
    size_t capacity;
} token_response_buffer;

static void token_secure_clear(void *memory, size_t length)
{
    volatile unsigned char *p = (volatile unsigned char *)memory;
    while (length-- > 0)
        *p++ = 0;
}

static void token_json_skip_ws(token_json_parser *parser)
{
    while (parser->position < parser->length) {
        unsigned char c = (unsigned char)parser->data[parser->position];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n')
            break;
        parser->position++;
    }
}

static int token_json_parse_string(token_json_parser *parser, char *output,
                                   size_t output_capacity, size_t *output_length)
{
    size_t used = 0;

    if (parser->position >= parser->length ||
        parser->data[parser->position] != '"')
        return -1;

    parser->position++;
    while (parser->position < parser->length) {
        unsigned char c = (unsigned char)parser->data[parser->position++];

        if (c == '"') {
            if (output_capacity == 0 || used >= output_capacity)
                return -1;
            output[used] = '\0';
            *output_length = used;
            return 0;
        }

        if (c == '\\') {
            if (parser->position >= parser->length)
                return -1;

            c = (unsigned char)parser->data[parser->position++];
            switch (c) {
            case '"':
            case '\\':
            case '/':
                break;
            case 'b':
                c = '\b';
                break;
            case 'f':
                c = '\f';
                break;
            case 'n':
                c = '\n';
                break;
            case 'r':
                c = '\r';
                break;
            case 't':
                c = '\t';
                break;
            case 'u': {
                unsigned int codepoint = 0;
                size_t i;

                if (parser->length - parser->position < 4)
                    return -1;
                for (i = 0; i < 4; i++) {
                    unsigned char h =
                        (unsigned char)parser->data[parser->position++];
                    if (h >= '0' && h <= '9')
                        codepoint = (codepoint << 4) | (unsigned int)(h - '0');
                    else if (h >= 'a' && h <= 'f')
                        codepoint = (codepoint << 4) |
                                    (unsigned int)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F')
                        codepoint = (codepoint << 4) |
                                    (unsigned int)(h - 'A' + 10);
                    else
                        return -1;
                }

                /*
                 * Credentials and JSON property names accepted here are
                 * intentionally restricted to ASCII.
                 */
                if (codepoint > 0x7f)
                    return -1;
                c = (unsigned char)codepoint;
                break;
            }
            default:
                return -1;
            }
        } else if (c < 0x20 || c > 0x7e) {
            return -1;
        }

        if (used + 1 >= output_capacity)
            return -1;
        output[used++] = (char)c;
    }

    return -1;
}

static int token_json_parse_file(const char *data, size_t length,
                                 char *token, size_t token_capacity,
                                 size_t *token_length)
{
    token_json_parser parser;
    char key[64];
    size_t key_length = 0;
    size_t value_length = 0;
    size_t i;

    parser.data = data;
    parser.length = length;
    parser.position = 0;

    token_json_skip_ws(&parser);
    if (parser.position >= parser.length || parser.data[parser.position++] != '{')
        return -1;

    token_json_skip_ws(&parser);
    if (token_json_parse_string(&parser, key, sizeof(key), &key_length) != 0 ||
        key_length != sizeof("access_token") - 1 ||
        memcmp(key, "access_token", sizeof("access_token") - 1) != 0)
        return -1;

    token_json_skip_ws(&parser);
    if (parser.position >= parser.length || parser.data[parser.position++] != ':')
        return -1;

    token_json_skip_ws(&parser);
    if (token_json_parse_string(&parser, token, token_capacity, &value_length) != 0 ||
        value_length == 0)
        return -1;

    for (i = 0; i < value_length; i++) {
        unsigned char c = (unsigned char)token[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '-' || c == '.' || c == '_' || c == '~' ||
              c == '+' || c == '/' || c == '=')) {
            token_secure_clear(token, token_capacity);
            return -1;
        }
    }

    token_json_skip_ws(&parser);
    if (parser.position >= parser.length || parser.data[parser.position++] != '}') {
        token_secure_clear(token, token_capacity);
        return -1;
    }

    token_json_skip_ws(&parser);
    if (parser.position != parser.length) {
        token_secure_clear(token, token_capacity);
        return -1;
    }

    *token_length = value_length;
    return 0;
}

static int token_json_escape_string(const char *input, size_t input_length,
                                    char *output, size_t output_capacity,
                                    size_t *output_length)
{
    static const char hex[] = "0123456789abcdef";
    size_t used = 0;
    size_t i;

    if (output_capacity == 0)
        return -1;

    for (i = 0; i < input_length; i++) {
        unsigned char c = (unsigned char)input[i];

        if (c == '"' || c == '\\') {
            if (output_capacity - used < 3)
                return -1;
            output[used++] = '\\';
            output[used++] = (char)c;
        } else if (c < 0x20) {
            if (output_capacity - used < 7)
                return -1;
            output[used++] = '\\';
            output[used++] = 'u';
            output[used++] = '0';
            output[used++] = '0';
            output[used++] = hex[c >> 4];
            output[used++] = hex[c & 0x0f];
        } else {
            if (used + 1 >= output_capacity)
                return -1;
            output[used++] = (char)c;
        }
    }

    if (used >= output_capacity)
        return -1;
    output[used] = '\0';
    *output_length = used;
    return 0;
}

static size_t token_response_write(char *data, size_t size, size_t count,
                                  void *userdata)
{
    token_response_buffer *response = (token_response_buffer *)userdata;
    size_t bytes;

    if (size != 0 && count > SIZE_MAX / size)
        return 0;
    bytes = size * count;

    if (bytes > response->capacity - response->length)
        return 0;

    memcpy(response->data + response->length, data, bytes);
    response->length += bytes;
    return bytes;
}

static int token_json_response_success(const char *data, size_t length)
{
    token_json_parser parser;
    char key[32];
    size_t key_length = 0;

    parser.data = data;
    parser.length = length;
    parser.position = 0;

    token_json_skip_ws(&parser);
    if (parser.position >= parser.length || parser.data[parser.position++] != '{')
        return 0;
    token_json_skip_ws(&parser);

    if (token_json_parse_string(&parser, key, sizeof(key), &key_length) != 0 ||
        key_length != sizeof("success") - 1 ||
        memcmp(key, "success", sizeof("success") - 1) != 0)
        return 0;

    token_json_skip_ws(&parser);
    if (parser.position >= parser.length || parser.data[parser.position++] != ':')
        return 0;
    token_json_skip_ws(&parser);

    if (parser.length - parser.position < 4 ||
        memcmp(parser.data + parser.position, "true", 4) != 0)
        return 0;
    parser.position += 4;

    token_json_skip_ws(&parser);
    if (parser.position >= parser.length || parser.data[parser.position++] != '}')
        return 0;
    token_json_skip_ws(&parser);

    return parser.position == parser.length;
}

/*
 * Dependencies: libc, libcurl, libssl and libcrypto (as required by the
 * libcurl TLS backend). Configure CORP_INGESTION_HTTPS_URL to the service's
 * HTTPS endpoint. The service is expected to accept a Bearer access token and
 * respond with JSON containing exactly {"success":true}.
 *
 * Returns 0 only after an HTTPS 2xx response with explicit success confirmation;
 * otherwise returns -1. The token is sent only in the TLS-protected
 * Authorization header, never in the JSON request body.
 */
int token_e_transmissao_http(void)
{
    FILE *file = NULL;
    char *file_data = NULL;
    char *token = NULL;
    char *hostname_json = NULL;
    char *request_body = NULL;
    char *authorization = NULL;
    char *response_data = NULL;
    char hostname[HOSTNAME_MAX_SIZE];
    const char *endpoint;
    size_t file_length;
    size_t token_length = 0;
    size_t hostname_length;
    size_t escaped_hostname_length = 0;
    size_t request_body_capacity;
    size_t authorization_capacity;
    size_t response_length = 0;
    size_t response_capacity = RESPONSE_MAX_SIZE;
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    CURLU *url = NULL;
    CURLUcode url_result;
    char *scheme = NULL;
    char *host = NULL;
    char *url_user = NULL;
    char *url_password = NULL;
    CURLcode curl_result;
    long http_status = 0;
    int curl_global_ready = 0;
    int result = -1;
    token_response_buffer response;

    memset(hostname, 0xa5, sizeof(hostname));

    file_data = (char *)malloc(TOKEN_MAX_FILE_SIZE + 1U);
    token = (char *)calloc(TOKEN_MAX_VALUE_SIZE + 1U, 1);
    response_data = (char *)malloc(response_capacity);
    if (file_data == NULL || token == NULL || response_data == NULL)
        goto cleanup;

    file = fopen(TOKEN_FILE_PATH, "rb");
    if (file == NULL)
        goto cleanup;

    file_length = fread(file_data, 1, TOKEN_MAX_FILE_SIZE + 1U, file);
    if (ferror(file) || file_length > TOKEN_MAX_FILE_SIZE)
        goto cleanup;

    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    if (token_json_parse_file(file_data, file_length, token,
                              TOKEN_MAX_VALUE_SIZE + 1U, &token_length) != 0)
        goto cleanup;

    if (gethostname(hostname, sizeof(hostname)) != 0 ||
        memchr(hostname, '\0', sizeof(hostname)) == NULL)
        goto cleanup;

    hostname_length = strnlen(hostname, sizeof(hostname));
    if (hostname_length == 0 || hostname_length >= sizeof(hostname))
        goto cleanup;

    {
        size_t i;
        for (i = 0; i < hostname_length; i++) {
            unsigned char c = (unsigned char)hostname[i];
            if (!((c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') ||
                  c == '.' || c == '-' || c == '_'))
                goto cleanup;
        }
    }

    if (hostname_length > (SIZE_MAX - 1U) / 6U)
        goto cleanup;
    hostname_json = (char *)malloc(hostname_length * 6U + 1U);
    if (hostname_json == NULL ||
        token_json_escape_string(hostname, hostname_length, hostname_json,
                                 hostname_length * 6U + 1U,
                                 &escaped_hostname_length) != 0)
        goto cleanup;

    if (escaped_hostname_length > SIZE_MAX - sizeof("{\"machine_label\":\"\"}"))
        goto cleanup;
    request_body_capacity = escaped_hostname_length +
                            sizeof("{\"machine_label\":\"\"}");
    request_body = (char *)malloc(request_body_capacity);
    if (request_body == NULL)
        goto cleanup;
    if (snprintf(request_body, request_body_capacity,
                 "{\"machine_label\":\"%s\"}", hostname_json) < 0)
        goto cleanup;

    endpoint = getenv("CORP_INGESTION_HTTPS_URL");
    if (endpoint == NULL || endpoint[0] == '\0' ||
        strnlen(endpoint, URL_MAX_SIZE + 1U) > URL_MAX_SIZE)
        goto cleanup;

    url = curl_url();
    if (url == NULL)
        goto cleanup;
    url_result = curl_url_set(url, CURLUPART_URL, endpoint, 0);
    if (url_result != CURLUE_OK)
        goto cleanup;

    if (curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
        curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK ||
        host == NULL || host[0] == '\0' ||
        strcasecmp(scheme, "https") != 0)
        goto cleanup;

    if (curl_url_get(url, CURLUPART_USER, &url_user, 0) == CURLUE_OK ||
        curl_url_get(url, CURLUPART_PASSWORD, &url_password, 0) == CURLUE_OK)
        goto cleanup;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        goto cleanup;
    curl_global_ready = 1;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    if (token_length > SIZE_MAX - sizeof("Authorization: Bearer "))
        goto cleanup;
    authorization_capacity = token_length + sizeof("Authorization: Bearer ");
    authorization = (char *)malloc(authorization_capacity);
    if (authorization == NULL)
        goto cleanup;

    if (snprintf(authorization, authorization_capacity,
                 "Authorization: Bearer %s", token) < 0)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;
    {
        struct curl_slist *new_headers = curl_slist_append(headers, authorization);
        if (new_headers == NULL)
            goto cleanup;
        headers = new_headers;
    }

    response.data = response_data;
    response.length = 0;
    response.capacity = response_capacity;

    curl_result = curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    if (curl_result != CURLE_OK)
        goto cleanup;
    if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                         (long)strlen(request_body)) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, token_response_write) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        goto cleanup;

    curl_result = curl_easy_perform(curl);
    if (curl_result != CURLE_OK)
        goto cleanup;
    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status) != CURLE_OK ||
        http_status < 200 || http_status >= 300)
        goto cleanup;

    response_length = response.length;
    if (!token_json_response_success(response.data, response_length))
        goto cleanup;

    result = 0;

cleanup:
    if (file != NULL)
        (void)fclose(file);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    if (headers != NULL)
        curl_slist_free_all(headers);
    if (curl_global_ready)
        curl_global_cleanup();
    if (url != NULL)
        curl_url_cleanup(url);
    if (scheme != NULL)
        curl_free(scheme);
    if (host != NULL)
        curl_free(host);
    if (url_user != NULL)
        curl_free(url_user);
    if (url_password != NULL)
        curl_free(url_password);
    if (authorization != NULL) {
        token_secure_clear(authorization, strlen(authorization));
        free(authorization);
    }
    if (token != NULL) {
        token_secure_clear(token, TOKEN_MAX_VALUE_SIZE + 1U);
        free(token);
    }
    if (file_data != NULL) {
        token_secure_clear(file_data, TOKEN_MAX_FILE_SIZE + 1U);
        free(file_data);
    }
    if (response_data != NULL) {
        token_secure_clear(response_data, response_capacity);
        free(response_data);
    }
    if (hostname_json != NULL)
        free(hostname_json);
    if (request_body != NULL)
        free(request_body);
    token_secure_clear(hostname, sizeof(hostname));

    return result;
}