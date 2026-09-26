#define _GNU_SOURCE
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    if (!endpoint || !token_json)
        return -1;

    CURL *curl = curl_easy_init();
    if (!curl)
        return -1;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        curl_easy_cleanup(curl);
        return -1;
    }

    CURLcode res;
    long http_code = 0;

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(token_json));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return -1;
    }

    res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
        return -1;

    return (http_code == 200) ? 0 : -1;
}