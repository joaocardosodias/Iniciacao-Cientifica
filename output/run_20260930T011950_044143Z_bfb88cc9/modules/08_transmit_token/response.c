#define _GNU_SOURCE
#include <curl/curl.h>
#include <stddef.h>
#include <string.h>

static size_t discard_response(char *data, size_t size, size_t nmemb,
                               void *userdata)
{
    (void)data;
    (void)userdata;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_json)
{
    CURL *curl;
    struct curl_slist *headers = NULL;
    CURLcode result;
    long status = 0;
    int rc = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL)
        return -1;

    curl = curl_easy_init();
    if (curl == NULL) {
        curl_slist_free_all(headers);
        return -1;
    }

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK) {
        goto cleanup;
    }

    result = curl_easy_perform(curl);
    if (result == CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK &&
        status == 200)
        rc = 0;

cleanup:
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return rc;
}