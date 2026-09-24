#define _GNU_SOURCE
#include <curl/curl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t discard_response(char *data, size_t size, size_t nmemb, void *userdata)
{
    (void)data;
    (void)userdata;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    unsigned char *body = NULL;
    size_t length = 0;
    size_t capacity = 1;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode curl_result;
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
        unsigned char chunk[8192];
        size_t count = fread(chunk, 1, sizeof(chunk), file);

        if (count != 0) {
            size_t needed;
            size_t new_capacity;
            unsigned char *new_body;

            if (count > SIZE_MAX - length - 1)
                goto cleanup;
            needed = length + count + 1;

            if (needed > capacity) {
                new_capacity = capacity;
                while (new_capacity < needed) {
                    if (new_capacity > SIZE_MAX / 2) {
                        new_capacity = needed;
                        break;
                    }
                    new_capacity *= 2;
                }
                new_body = realloc(body, new_capacity);
                if (new_body == NULL)
                    goto cleanup;
                body = new_body;
                capacity = new_capacity;
            }

            memcpy(body + length, chunk, count);
            length += count;
        }

        if (count < sizeof(chunk)) {
            if (ferror(file))
                goto cleanup;
            break;
        }
    }

    body[length] = '\0';
    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    if (length > (size_t)LLONG_MAX)
        goto cleanup;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        goto cleanup;

    curl_result = curl_easy_perform(curl);
    if (curl_result != CURLE_OK)
        goto cleanup;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
        goto cleanup;

    if (status == 200)
        result = 0;

cleanup:
    if (file != NULL)
        fclose(file);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(body);
    return result;
}