#define _GNU_SOURCE
#include <curl/curl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static size_t discard_response(char *data, size_t size, size_t nmemb, void *context)
{
    (void)data;
    (void)context;
    return size * nmemb;
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
    int result = -1;

    if (endpoint == NULL || token_path == NULL)
        return -1;

    file = fopen(token_path, "rb");
    if (file == NULL)
        goto cleanup;

    body = malloc(capacity);
    if (body == NULL)
        goto cleanup;

    for (;;) {
        size_t available = capacity - length - 1;
        size_t count;

        if (available == 0) {
            size_t new_capacity;
            char *new_body;

            if (length >= (size_t)LLONG_MAX || capacity == SIZE_MAX)
                goto cleanup;

            new_capacity = capacity > SIZE_MAX / 2 ? SIZE_MAX : capacity * 2;
            new_body = realloc(body, new_capacity);
            if (new_body == NULL)
                goto cleanup;

            body = new_body;
            capacity = new_capacity;
            continue;
        }

        count = fread(body + length, 1, available, file);
        length += count;

        if (count == 0) {
            if (ferror(file))
                goto cleanup;
            break;
        }

        if (length > (size_t)LLONG_MAX)
            goto cleanup;
    }

    body[length] = '\0';

    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                         discard_response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        goto cleanup;

    if (curl_easy_perform(curl) != CURLE_OK ||
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
        goto cleanup;

    if (status == 200)
        result = 0;

cleanup:
    curl_slist_free_all(headers);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    free(body);
    if (file != NULL)
        fclose(file);
    return result;
}