#define _GNU_SOURCE
#include <curl/curl.h>
#include <pthread.h>
#include <stddef.h>
#include <string.h>

static pthread_once_t curl_init_once = PTHREAD_ONCE_INIT;
static CURLcode curl_init_status;

static void initialize_curl(void)
{
    curl_init_status = curl_global_init(CURL_GLOBAL_DEFAULT);
}

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

    if (pthread_once(&curl_init_once, initialize_curl) != 0 ||
        curl_init_status != CURLE_OK)
        return -1;

    CURL *curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    struct curl_slist *headers =
        curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL) {
        curl_easy_cleanup(curl);
        return -1;
    }

    CURLcode result = CURLE_OK;
    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)strlen(token_json)) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK) {
        result = CURLE_FAILED_INIT;
    } else {
        result = curl_easy_perform(curl);
    }

    long status = 0;
    if (result == CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK)
        result = CURLE_FAILED_INIT;

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return result == CURLE_OK && status == 200 ? 0 : -1;
}