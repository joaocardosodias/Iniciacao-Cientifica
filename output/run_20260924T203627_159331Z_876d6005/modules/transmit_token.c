#define _GNU_SOURCE
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    unsigned char *body = NULL;
    size_t length = 0;
    size_t capacity = 8192;
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    CURLcode result;
    long status = 0;
    int success = 0;

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
            size_t new_capacity = capacity * 2;
            unsigned char *new_body;

            if (new_capacity <= capacity)
                goto cleanup;
            new_body = realloc(body, new_capacity);
            if (new_body == NULL)
                goto cleanup;
            body = new_body;
            capacity = new_capacity;
            available = capacity - length - 1;
        }

        count = fread(body + length, 1, available, file);
        length += count;
        body[length] = '\0';

        if (count == 0) {
            if (ferror(file))
                goto cleanup;
            if (feof(file))
                break;
        }
    }

    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

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
    result = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (result != CURLE_OK)
        goto cleanup;
    result = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    if (result != CURLE_OK)
        goto cleanup;
    result = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)length);
    if (result != CURLE_OK)
        goto cleanup;
    result = curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (result != CURLE_OK)
        goto cleanup;

    result = curl_easy_perform(curl);
    if (result != CURLE_OK)
        goto cleanup;
    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
        goto cleanup;

    success = (status == 200);

cleanup:
    if (file != NULL)
        fclose(file);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(body);
    return success ? 0 : -1;
}