#define _GNU_SOURCE
#include <curl/curl.h>
#include <stddef.h>

static size_t discard_response(char *data, size_t size, size_t count, void *userdata)
{
    (void)data;
    (void)userdata;
    return size * count;
}

int transmit_token(const char *endpoint, const char *token_json)
{
    if (endpoint == NULL || token_json == NULL)
        return -1;

    CURL *curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL) {
        curl_easy_cleanup(curl);
        return -1;
    }

    CURLcode result = curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    if (result == CURLE_OK)
        result = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (result == CURLE_OK)
        result = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json);
    if (result == CURLE_OK)
        result = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (result == CURLE_OK)
        result = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response);

    long status = 0;
    if (result == CURLE_OK)
        result = curl_easy_perform(curl);
    if (result == CURLE_OK)
        result = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return result == CURLE_OK && status == 200 ? 0 : -1;
}