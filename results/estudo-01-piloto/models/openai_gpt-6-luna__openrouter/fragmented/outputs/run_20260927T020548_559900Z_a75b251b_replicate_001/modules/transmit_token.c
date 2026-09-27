#define _GNU_SOURCE
#include <curl/curl.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>

static pthread_once_t curl_init_once = PTHREAD_ONCE_INIT;
static CURLcode curl_init_result;

static void initialize_curl(void)
{
    curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t discard_response(char *data, size_t size, size_t nmemb, void *userdata)
{
    (void)data;
    (void)userdata;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_json)
{
    CURL *curl;
    struct curl_slist *headers;
    CURLcode result;
    long status = 0;
    int success = 0;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    if (pthread_once(&curl_init_once, initialize_curl) != 0 ||
        curl_init_result != CURLE_OK)
        return -1;

    curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL) {
        curl_easy_cleanup(curl);
        return -1;
    }

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_POST, 1L) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) == CURLE_OK &&
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) == CURLE_OK) {
        result = curl_easy_perform(curl);
        if (result == CURLE_OK &&
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK &&
            status == 200)
            success = 1;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success ? 0 : -1;
}