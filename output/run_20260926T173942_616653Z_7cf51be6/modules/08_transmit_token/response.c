#define _GNU_SOURCE
#include <curl/curl.h>
#include <string.h>

int transmit_token(const char *endpoint, const char *token_json)
{
    CURL *curl;
    CURLcode rc;
    long http_code = 0;
    struct curl_slist *hdrs = NULL;
    int result = -1;

    if (!endpoint || !token_json)
        return -1;

    curl = curl_easy_init();
    if (!curl)
        return -1;

    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    if (!hdrs) {
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(token_json));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code) == CURLE_OK) {
            if (http_code == 200)
                result = 0;
        }
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    return result;
}