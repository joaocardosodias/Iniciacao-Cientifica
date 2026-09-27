#define _GNU_SOURCE
#include <curl/curl.h>
#include <stddef.h>
#include <string.h>

static size_t discard_response(char *data, size_t size, size_t count, void *user_data)
{
    (void)data;
    (void)user_data;
    return size * count;
}

int transmit_token(const char *endpoint, const char *token_json)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode result;
    long response_code = 0;
    size_t body_length;
    int status = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return -1;

    body_length = strlen(token_json);
    curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        goto cleanup;

    result = curl_easy_perform(curl);
    if (result == CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) == CURLE_OK &&
        response_code == 200)
        status = 0;

cleanup:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return status;
}