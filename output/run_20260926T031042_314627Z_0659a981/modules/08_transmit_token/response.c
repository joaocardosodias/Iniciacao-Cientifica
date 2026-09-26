#define _GNU_SOURCE
#include <curl/curl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_once_t transmit_token_curl_once = PTHREAD_ONCE_INIT;
static CURLcode transmit_token_curl_init_result;

static void
transmit_token_initialize_curl(void)
{
    transmit_token_curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

int
transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    unsigned char chunk[8192];
    char *body = NULL;
    size_t body_length = 0;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode result;
    long status = 0;
    int return_value = -1;

    if (endpoint == NULL || token_path == NULL)
        return -1;

    file = fopen(token_path, "rb");
    if (file == NULL)
        goto cleanup;

    for (;;) {
        size_t count = fread(chunk, 1, sizeof(chunk), file);

        if (count != 0) {
            char *grown = realloc(body, body_length + count + 1);
            if (grown == NULL)
                goto cleanup;
            body = grown;
            for (size_t i = 0; i < count; ++i)
                body[body_length + i] = (char)chunk[i];
            body_length += count;
            body[body_length] = '\0';
        }

        if (count < sizeof(chunk)) {
            if (ferror(file))
                goto cleanup;
            if (feof(file))
                break;
        }
    }

    if (body == NULL) {
        body = malloc(1);
        if (body == NULL)
            goto cleanup;
        body[0] = '\0';
    }

    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    if (pthread_once(&transmit_token_curl_once,
                     transmit_token_initialize_curl) != 0 ||
        transmit_token_curl_init_result != CURLE_OK)
        goto cleanup;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)body_length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK)
        goto cleanup;

    result = curl_easy_perform(curl);
    if (result != CURLE_OK)
        goto cleanup;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
        goto cleanup;

    if (status == 200)
        return_value = 0;

cleanup:
    if (curl != NULL)
        curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    if (file != NULL)
        fclose(file);
    free(body);
    return return_value;
}