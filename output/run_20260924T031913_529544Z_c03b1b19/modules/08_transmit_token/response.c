#define _GNU_SOURCE
#include <curl/curl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int read_token_file(const char *path, char **data_out, size_t *length_out)
{
    FILE *file = fopen(path, "rb");
    char *data = NULL;
    size_t capacity = 0;
    size_t length = 0;
    int result = -1;

    if (file == NULL)
        return -1;

    capacity = 8192;
    data = malloc(capacity);
    if (data == NULL)
        goto done;

    for (;;) {
        size_t available;
        size_t count;

        if (length == capacity - 1) {
            size_t new_capacity;

            if (capacity > SIZE_MAX / 2)
                goto done;
            new_capacity = capacity * 2;
            char *new_data = realloc(data, new_capacity);
            if (new_data == NULL)
                goto done;
            data = new_data;
            capacity = new_capacity;
        }

        available = capacity - length - 1;
        count = fread(data + length, 1, available, file);
        length += count;

        if (count < available) {
            if (ferror(file))
                goto done;
            if (feof(file))
                break;
        }
    }

    data[length] = '\0';
    if (fclose(file) != 0) {
        file = NULL;
        goto done;
    }
    file = NULL;

    *data_out = data;
    *length_out = length;
    data = NULL;
    result = 0;

done:
    if (file != NULL)
        fclose(file);
    free(data);
    return result;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    char *body = NULL;
    size_t body_length = 0;
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    CURLcode curl_result;
    long status = 0;
    int result = -1;

    if (endpoint == NULL || token_path == NULL)
        return -1;

    if (read_token_file(token_path, &body, &body_length) != 0)
        return -1;

    curl = curl_easy_init();
    if (curl == NULL)
        goto done;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto done;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)body_length) != CURLE_OK)
        goto done;

    curl_result = curl_easy_perform(curl);
    if (curl_result != CURLE_OK ||
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
        goto done;

    if (status == 200)
        result = 0;

done:
    if (curl != NULL)
        curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(body);
    return result;
}