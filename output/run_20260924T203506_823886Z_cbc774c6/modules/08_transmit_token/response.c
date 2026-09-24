#define _GNU_SOURCE
#include <curl/curl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    char *body = NULL;
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    size_t capacity = 8192;
    size_t length = 0;
    long status = 0;
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
        size_t count = fread(body + length, 1, capacity - length, file);
        length += count;

        if (ferror(file))
            goto done;
        if (feof(file))
            break;

        if (length == capacity) {
            char *larger;

            if (capacity > (SIZE_MAX - 1) / 2)
                goto done;
            capacity *= 2;
            larger = realloc(body, capacity + 1);
            if (larger == NULL)
                goto done;
            body = larger;
        }
    }

    if (fclose(file) != 0) {
        file = NULL;
        goto done;
    }
    file = NULL;

    if (length > (size_t)LLONG_MAX)
        goto done;
    body[length] = '\0';

    curl = curl_easy_init();
    if (curl == NULL)
        goto done;

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL)
        goto done;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) != CURLE_OK)
        goto done;

    if (curl_easy_perform(curl) != CURLE_OK ||
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
        goto done;

    if (status == 200)
        result = 0;

done:
    if (file != NULL)
        fclose(file);
    curl_slist_free_all(headers);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    free(body);
    return result;
}