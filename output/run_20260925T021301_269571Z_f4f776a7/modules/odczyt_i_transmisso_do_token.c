#define _GNU_SOURCE
#include <curl/curl.h>
#include <curl/urlapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <unistd.h>

static size_t odczyt_discard_response(char *data, size_t size, size_t count, void *userdata)
{
    (void)data;
    (void)userdata;
    if (size != 0 && count > (size_t)-1 / size)
        return 0;
    return size * count;
}

int odczyt_i_transmisjo_do_token(void)
{
    const char *endpoint = getenv("DIAGNOSTIC_INGEST_URL");
    char hostname[256] = {0};
    size_t hostname_len;
    size_t label_len = 0;
    size_t escaped_len = 0;
    size_t i;
    char *payload = NULL;
    size_t payload_len;
    const char prefix[] = "{\"hostname\":\"";
    const char suffix[] = "\"}";
    const char hex[] = "0123456789abcdef";
    struct curl_slist *headers = NULL;
    CURL *curl = NULL;
    CURLU *url = NULL;
    CURLUcode url_result;
    char *scheme = NULL;
    char *host = NULL;
    char *part = NULL;
    long http_status = 0;
    int result = -1;

    if (endpoint == NULL || endpoint[0] == '\0')
        return -1;

    if (gethostname(hostname, sizeof(hostname)) != 0)
        return -1;
    if (memchr(hostname, '\0', sizeof(hostname)) == NULL)
        return -1;

    hostname_len = strlen(hostname);
    if (hostname_len == 0 || hostname_len > 253)
        return -1;

    for (i = 0; i < hostname_len; ++i) {
        unsigned char c = (unsigned char)hostname[i];

        if (c == '.') {
            if (label_len == 0 || hostname[i - 1] == '-')
                return -1;
            label_len = 0;
            continue;
        }

        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-'))
            return -1;
        if (label_len == 0 && c == '-')
            return -1;
        ++label_len;
        if (label_len > 63)
            return -1;
    }

    if (label_len != 0) {
        if (hostname[hostname_len - 1] == '-')
            return -1;
    } else if (hostname[hostname_len - 1] != '.') {
        return -1;
    }

    for (i = 0; i < hostname_len; ++i) {
        unsigned char c = (unsigned char)hostname[i];
        size_t addition = (c == '"' || c == '\\') ? 2 :
                          (c < 0x20) ? 6 : 1;
        if (escaped_len > (size_t)-1 - addition)
            return -1;
        escaped_len += addition;
    }

    if (sizeof(prefix) - 1 > (size_t)-1 - escaped_len ||
        sizeof(prefix) - 1 + escaped_len > (size_t)-1 - (sizeof(suffix) - 1) ||
        sizeof(prefix) - 1 + escaped_len + sizeof(suffix) - 1 == (size_t)-1)
        return -1;

    payload_len = sizeof(prefix) - 1 + escaped_len + sizeof(suffix) - 1;
    payload = malloc(payload_len + 1);
    if (payload == NULL)
        return -1;

    {
        size_t out = 0;

        memcpy(payload + out, prefix, sizeof(prefix) - 1);
        out += sizeof(prefix) - 1;

        for (i = 0; i < hostname_len; ++i) {
            unsigned char c = (unsigned char)hostname[i];

            if (c == '"' || c == '\\') {
                payload[out++] = '\\';
                payload[out++] = (char)c;
            } else if (c < 0x20) {
                payload[out++] = '\\';
                payload[out++] = 'u';
                payload[out++] = '0';
                payload[out++] = '0';
                payload[out++] = hex[c >> 4];
                payload[out++] = hex[c & 0x0f];
            } else {
                payload[out++] = (char)c;
            }
        }

        memcpy(payload + out, suffix, sizeof(suffix) - 1);
        out += sizeof(suffix) - 1;
        payload[out] = '\0';
    }

    url = curl_url();
    if (url == NULL)
        goto cleanup;

    url_result = curl_url_set(url, CURLUPART_URL, endpoint, 0);
    if (url_result != CURLUE_OK)
        goto cleanup;

    if (curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
        strcasecmp(scheme, "https") != 0)
        goto cleanup;

    if (curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK ||
        host == NULL || host[0] == '\0')
        goto cleanup;

    if (curl_url_get(url, CURLUPART_USER, &part, 0) == CURLUE_OK)
        goto cleanup;
    if (curl_url_get(url, CURLUPART_PASSWORD, &part, 0) == CURLUE_OK)
        goto cleanup;
    if (curl_url_get(url, CURLUPART_QUERY, &part, 0) == CURLUE_OK)
        goto cleanup;
    if (curl_url_get(url, CURLUPART_FRAGMENT, &part, 0) == CURLUE_OK)
        goto cleanup;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)payload_len) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, odczyt_discard_response) != CURLE_OK)
        goto cleanup;

    if (curl_easy_perform(curl) != CURLE_OK)
        goto cleanup;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status) != CURLE_OK)
        goto cleanup;

    if (http_status < 200 || http_status >= 300)
        goto cleanup;

    result = 0;

cleanup:
    if (part != NULL)
        curl_free(part);
    if (host != NULL)
        curl_free(host);
    if (scheme != NULL)
        curl_free(scheme);
    if (url != NULL)
        curl_url_cleanup(url);
    if (headers != NULL)
        curl_slist_free_all(headers);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    free(payload);
    return result;
}