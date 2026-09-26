#define _GNU_SOURCE
#include <curl/curl.h>
#include <stddef.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    if (!endpoint || !token_json)
        return -1;

    CURL *curl = NULL;
    struct curl_slist *hdrs = NULL;
    long resp_code = 0;
    CURLcode rc;

    rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK)
        return -1;

    curl = curl_easy_init();
    if (!curl) {
        curl_global_cleanup();
        return -1;
    }

    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    if (!hdrs) {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(token_json));

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return -1;
    }

    rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &resp_code);
    if (rc != CURLE_OK) {
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(curl);
        curl_global_cleanup();
        return -1;
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    return (resp_code == 200) ? 0 : -1;
}