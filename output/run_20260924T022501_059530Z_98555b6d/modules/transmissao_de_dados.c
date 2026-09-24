#define _GNU_SOURCE
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#define TOKEN_FILE_PATH "/tmp/.session.token"
#define SERVICE_CONFIG_PATH "/etc/corporate-management.json"
#define MAX_INPUT_SIZE 16384U
#define MAX_TOKEN_SIZE 4096U
#define MAX_RESPONSE_SIZE 65536U
#define CONNECT_TIMEOUT_SECONDS 5L
#define TOTAL_TIMEOUT_SECONDS 15L

struct response_buffer {
    char *data;
    size_t length;
};

static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static CURLcode curl_global_status = CURLE_FAILED_INIT;

static void initialize_curl(void)
{
    curl_global_status = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static json_object *parse_json_complete(const char *data, size_t length)
{
    struct json_tokener *tokener;
    json_object *object;
    enum json_tokener_error error;
    size_t parsed;
    size_t i;

    if (data == NULL || length == 0 || length > INT_MAX)
        return NULL;

    tokener = json_tokener_new();
    if (tokener == NULL)
        return NULL;

    object = json_tokener_parse_ex(tokener, data, (int)length);
    error = json_tokener_get_error(tokener);
    parsed = json_tokener_get_parse_end(tokener);

    if (error != json_tokener_success || object == NULL) {
        if (object != NULL)
            json_object_put(object);
        json_tokener_free(tokener);
        return NULL;
    }

    for (i = parsed; i < length; ++i) {
        if (!isspace((unsigned char)data[i])) {
            json_object_put(object);
            json_tokener_free(tokener);
            return NULL;
        }
    }

    json_tokener_free(tokener);
    return object;
}

static int read_secure_config(char *buffer, size_t capacity, size_t *length)
{
    int fd;
    FILE *file;
    struct stat st;
    size_t count;
    int read_error;
    int close_error;

    if (buffer == NULL || capacity < 2 || length == NULL)
        return -1;

    fd = open(SERVICE_CONFIG_PATH, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        close(fd);
        return -1;
    }

    file = fdopen(fd, "r");
    if (file == NULL) {
        close(fd);
        return -1;
    }

    count = fread(buffer, 1, capacity, file);
    read_error = ferror(file);
    close_error = fclose(file);

    if (read_error || close_error != 0 || count == capacity)
        return -1;

    buffer[count] = '\0';
    *length = count;
    return 0;
}

static int append_response(char *data, size_t size, size_t count, void *userdata)
{
    struct response_buffer *response = userdata;
    size_t incoming;
    char *next;

    if (response == NULL || (data == NULL && size != 0 && count != 0))
        return 0;
    if (size != 0 && count > SIZE_MAX / size)
        return 0;

    incoming = size * count;
    if (incoming > MAX_RESPONSE_SIZE - response->length)
        return 0;

    next = realloc(response->data, response->length + incoming + 1);
    if (next == NULL)
        return 0;

    response->data = next;
    memcpy(response->data + response->length, data, incoming);
    response->length += incoming;
    response->data[response->length] = '\0';
    return incoming;
}

static void clear_header_list(struct curl_slist *headers)
{
    struct curl_slist *item;

    for (item = headers; item != NULL; item = item->next) {
        if (item->data != NULL)
            explicit_bzero(item->data, strlen(item->data));
    }
    curl_slist_free_all(headers);
}

static int validate_service_endpoint(const char *endpoint, const char *authorized_host)
{
    CURLU *url = NULL;
    CURLU *host_url = NULL;
    char *scheme = NULL;
    char *host = NULL;
    char *configured_host = NULL;
    char *username = NULL;
    char *password = NULL;
    char *port = NULL;
    CURLUcode result;
    int valid = 0;

    if (endpoint == NULL || authorized_host == NULL ||
        endpoint[0] == '\0' || authorized_host[0] == '\0')
        return 0;

    url = curl_url();
    host_url = curl_url();
    if (url == NULL || host_url == NULL)
        goto done;

    if (curl_url_set(url, CURLUPART_URL, endpoint, 0) != CURLUE_OK)
        goto done;
    if (curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
        strcasecmp(scheme, "https") != 0)
        goto done;
    if (curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK ||
        host[0] == '\0')
        goto done;

    result = curl_url_get(url, CURLUPART_USERNAME, &username, 0);
    if (result == CURLUE_OK)
        goto done;
    result = curl_url_get(url, CURLUPART_PASSWORD, &password, 0);
    if (result == CURLUE_OK)
        goto done;

    result = curl_url_get(url, CURLUPART_PORT, &port, 0);
    if (result == CURLUE_OK && strcmp(port, "443") != 0)
        goto done;
    if (result != CURLUE_OK && result != CURLUE_NO_PORT)
        goto done;

    if (curl_url_set(host_url, CURLUPART_URL, "https://", 0) != CURLUE_OK)
        goto done;
    if (curl_url_set(host_url, CURLUPART_HOST, authorized_host, 0) != CURLUE_OK)
        goto done;
    if (curl_url_get(host_url, CURLUPART_HOST, &configured_host, 0) != CURLUE_OK)
        goto done;

    valid = strcasecmp(host, configured_host) == 0;

done:
    curl_free(scheme);
    curl_free(host);
    curl_free(configured_host);
    curl_free(username);
    curl_free(password);
    curl_free(port);
    if (url != NULL)
        curl_url_cleanup(url);
    if (host_url != NULL)
        curl_url_cleanup(host_url);
    return valid;
}

static int response_indicates_success(const struct response_buffer *response)
{
    json_object *root;
    json_object *status_object;
    const char *status;
    int success = 0;

    if (response == NULL || response->data == NULL || response->length == 0)
        return 0;

    root = parse_json_complete(response->data, response->length);
    if (root == NULL || !json_object_is_type(root, json_type_object)) {
        if (root != NULL)
            json_object_put(root);
        return 0;
    }

    if (json_object_object_get_ex(root, "status", &status_object) &&
        json_object_is_type(status_object, json_type_string)) {
        status = json_object_get_string(status_object);
        success = status != NULL && strcmp(status, "success") == 0;
    }

    json_object_put(root);
    return success;
}

int transmissao_de_dados(void)
{
    char token_buffer[MAX_INPUT_SIZE + 1];
    char config_buffer[MAX_INPUT_SIZE + 1];
    char hostname[HOST_NAME_MAX + 1];
    size_t token_length = 0;
    size_t config_length = 0;
    size_t token_size;
    size_t authorization_length;
    size_t i;
    FILE *token_file = NULL;
    size_t bytes_read;
    int read_error;
    int close_error;
    json_object *token_root = NULL;
    json_object *token_object = NULL;
    json_object *config_root = NULL;
    json_object *endpoint_object = NULL;
    json_object *host_object = NULL;
    json_object *body_root = NULL;
    json_object *machine_object = NULL;
    const char *token_value;
    const char *endpoint;
    const char *authorized_host;
    const char *body;
    char *authorization = NULL;
    const char *token_header = NULL;
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    CURLcode curl_status;
    long http_status = 0;
    struct response_buffer response = { NULL, 0 };
    int result = -1;

    memset(token_buffer, 0, sizeof(token_buffer));
    memset(config_buffer, 0, sizeof(config_buffer));
    memset(hostname, 0, sizeof(hostname));

    token_file = fopen(TOKEN_FILE_PATH, "rb");
    if (token_file == NULL)
        goto cleanup;

    bytes_read = fread(token_buffer, 1, sizeof(token_buffer), token_file);
    read_error = ferror(token_file);
    close_error = fclose(token_file);
    token_file = NULL;

    if (read_error || close_error != 0 || bytes_read == sizeof(token_buffer) ||
        bytes_read == 0 || bytes_read > MAX_INPUT_SIZE)
        goto cleanup;

    token_length = bytes_read;
    token_buffer[token_length] = '\0';
    token_root = parse_json_complete(token_buffer, token_length);
    if (token_root == NULL || !json_object_is_type(token_root, json_type_object))
        goto cleanup;

    if (!json_object_object_get_ex(token_root, "session_token", &token_object) ||
        !json_object_is_type(token_object, json_type_string))
        goto cleanup;

    token_value = json_object_get_string(token_object);
    token_size = (size_t)json_object_get_string_len(token_object);
    if (token_value == NULL || token_size == 0 || token_size > MAX_TOKEN_SIZE)
        goto cleanup;

    for (i = 0; i < token_size; ++i) {
        unsigned char c = (unsigned char)token_value[i];
        if (c < 0x21 || c > 0x7e)
            goto cleanup;
    }

    if (read_secure_config(config_buffer, sizeof(config_buffer), &config_length) != 0)
        goto cleanup;

    config_root = parse_json_complete(config_buffer, config_length);
    if (config_root == NULL || !json_object_is_type(config_root, json_type_object))
        goto cleanup;

    if (!json_object_object_get_ex(config_root, "endpoint", &endpoint_object) ||
        !json_object_is_type(endpoint_object, json_type_string) ||
        !json_object_object_get_ex(config_root, "authorized_host", &host_object) ||
        !json_object_is_type(host_object, json_type_string))
        goto cleanup;

    endpoint = json_object_get_string(endpoint_object);
    authorized_host = json_object_get_string(host_object);
    if (!validate_service_endpoint(endpoint, authorized_host))
        goto cleanup;

    if (gethostname(hostname, sizeof(hostname) - 1) != 0 ||
        memchr(hostname, '\0', sizeof(hostname)) == NULL ||
        hostname[0] == '\0')
        goto cleanup;

    body_root = json_object_new_object();
    machine_object = json_object_new_string(hostname);
    if (body_root == NULL || machine_object == NULL)
        goto cleanup;
    if (json_object_object_add(body_root, "machine_label", machine_object) != 0)
        goto cleanup;
    machine_object = NULL;

    body = json_object_to_json_string_ext(body_root, JSON_C_TO_STRING_PLAIN);
    if (body == NULL)
        goto cleanup;

    if (token_size > SIZE_MAX - sizeof("Authorization: Bearer "))
        goto cleanup;
    authorization_length = sizeof("Authorization: Bearer ") - 1 + token_size;
    authorization = malloc(authorization_length + 1);
    if (authorization == NULL)
        goto cleanup;

    memcpy(authorization, "Authorization: Bearer ", sizeof("Authorization: Bearer ") - 1);
    memcpy(authorization + sizeof("Authorization: Bearer ") - 1, token_value, token_size);
    authorization[authorization_length] = '\0';

    if (pthread_once(&curl_once, initialize_curl) != 0 ||
        curl_global_status != CURLE_OK)
        goto cleanup;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;
    token_header = authorization;
    headers = curl_slist_append(headers, token_header);
    if (headers == NULL)
        goto cleanup;

    curl_status = curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    if (curl_status != CURLE_OK)
        goto cleanup;
    if (curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https") != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https") != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT_SECONDS) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, TOTAL_TIMEOUT_SECONDS) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body)) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response) != CURLE_OK)
        goto cleanup;

    curl_status = curl_easy_perform(curl);
    if (curl_status != CURLE_OK)
        goto cleanup;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status) != CURLE_OK ||
        http_status != 200 || !response_indicates_success(&response))
        goto cleanup;

    result = 0;

cleanup:
    if (token_file != NULL)
        fclose(token_file);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    clear_header_list(headers);
    if (authorization != NULL) {
        explicit_bzero(authorization, authorization_length + 1);
        free(authorization);
    }
    if (response.data != NULL) {
        explicit_bzero(response.data, response.length);
        free(response.data);
    }
    if (machine_object != NULL)
        json_object_put(machine_object);
    if (body_root != NULL)
        json_object_put(body_root);
    if (config_root != NULL)
        json_object_put(config_root);
    if (token_root != NULL)
        json_object_put(token_root);
    explicit_bzero(token_buffer, sizeof(token_buffer));
    explicit_bzero(config_buffer, sizeof(config_buffer));
    explicit_bzero(hostname, sizeof(hostname));
    return result;
}