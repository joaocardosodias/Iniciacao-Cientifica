#define _GNU_SOURCE
#include <curl/curl.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    unsigned char *body = NULL;
    size_t length = 0;
    size_t capacity = 4096;
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    CURLcode result;
    long status = 0;
    int success = 0;

    if (endpoint == NULL || token_path == NULL ||
        (uintmax_t)SIZE_MAX > (uintmax_t)LLONG_MAX) {
        if ((uintmax_t)SIZE_MAX > (uintmax_t)LLONG_MAX)
            return -1;
        if (endpoint == NULL || token_path == NULL)
            return -1;
    }

    file = fopen(token_path, "rb");
    if (file == NULL)
        goto cleanup;

    body = malloc(capacity);
    if (body == NULL)
        goto cleanup;

    for (;;) {
        size_t count;

        if (length == capacity - 1) {
            size_t new_capacity;
            unsigned char *new_body;

            if (capacity > SIZE_MAX / 2)
                goto cleanup;
            new_capacity = capacity * 2;
            new_body = realloc(body, new_capacity);
            if (new_body == NULL)
                goto cleanup;
            body = new_body;
            capacity = new_capacity;
        }

        count = fread(body + length, 1, capacity - 1 - length, file);
        length += count;

        if (ferror(file))
            goto cleanup;
        if (feof(file))
            break;
        if (count == 0)
            goto cleanup;
    }

    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;
    body[length] = '\0';

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    result = curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    if (result != CURLE_OK)
        goto cleanup;
    result = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (result != CURLE_OK)
        goto cleanup;
    result = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    if (result != CURLE_OK)
        goto cleanup;
    result = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                             (curl_off_t)length);
    if (result != CURLE_OK)
        goto cleanup;
    result = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (result != CURLE_OK)
        goto cleanup;

    result = curl_easy_perform(curl);
    if (result != CURLE_OK)
        goto cleanup;

    result = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (result == CURLE_OK && status == 200)
        success = 1;

cleanup:
    if (file != NULL)
        fclose(file);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    if (headers != NULL)
        curl_slist_free_all(headers);
    free(body);

    return success ? 0 : -1;
}