#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

static size_t discard_response(char *data, size_t size, size_t count, void *context)
{
    (void)data;
    (void)context;

    if (count != 0 && size > SIZE_MAX / count)
        return 0;

    return size * count;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    char *body = NULL;
    size_t capacity = 8192;
    size_t length = 0;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    long status = 0;
    int curl_initialized = 0;
    int result = -1;

    if (endpoint == NULL || token_path == NULL)
        return -1;

    file = fopen(token_path, "rb");
    if (file == NULL)
        goto done;

    body = malloc(capacity + 1);
    if (body == NULL)
        goto done;

    for (;;) {
        size_t available;
        size_t nread;

        if (length == capacity) {
            size_t new_capacity;
            char *new_body;

            new_capacity = capacity > (SIZE_MAX - 1) / 2
                         ? SIZE_MAX - 1
                         : capacity * 2;
            if (new_capacity <= capacity)
                goto done;

            new_body = realloc(body, new_capacity + 1);
            if (new_body == NULL)
                goto done;

            body = new_body;
            capacity = new_capacity;
        }

        available = capacity - length;
        nread = fread(body + length, 1, available, file);
        length += nread;

        if (nread < available) {
            if (ferror(file))
                goto done;
            if (feof(file))
                break;
        }
    }

    body[length] = '\0';

    {
        int close_result = fclose(file);
        file = NULL;
        if (close_result != 0)
            goto done;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        goto done;
    curl_initialized = 1;

    curl = curl_easy_init();
    if (curl == NULL)
        goto done;

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL)
        goto done;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                         discard_response) != CURLE_OK)
        goto done;

    if (curl_easy_perform(curl) != CURLE_OK)
        goto done;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK &&
        status == 200)
        result = 0;

done:
    if (file != NULL)
        fclose(file);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    if (curl_initialized)
        curl_global_cleanup();
    free(body);

    return result;
}