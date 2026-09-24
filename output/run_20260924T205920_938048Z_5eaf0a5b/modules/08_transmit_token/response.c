#define _GNU_SOURCE
#include <curl/curl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static size_t discard_response(char *data, size_t size, size_t nmemb, void *userdata)
{
    (void)data;
    (void)userdata;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    char *body = NULL;
    size_t capacity = 8192;
    size_t length = 0;
    curl_off_t post_length;
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
        size_t nread;

        if (length == capacity - 1) {
            char *larger;

            if (capacity > SIZE_MAX / 2)
                goto cleanup;
            larger = realloc(body, capacity * 2);
            if (larger == NULL)
                goto cleanup;
            body = larger;
            capacity *= 2;
        }

        nread = fread(body + length, 1, capacity - length - 1, file);
        length += nread;

        if (ferror(file))
            goto cleanup;
        if (feof(file))
            break;
    }

    body[length] = '\0';
    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    post_length = (curl_off_t)length;
    if (post_length < 0 || (size_t)post_length != length)
        goto cleanup;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, post_length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK)
        goto cleanup;

    if (curl_easy_perform(curl) != CURLE_OK ||
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
        goto cleanup;

    if (status == 200)
        result = 0;

cleanup:
    if (file != NULL)
        fclose(file);
    curl_slist_free_all(headers);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    free(body);
    return result;
}