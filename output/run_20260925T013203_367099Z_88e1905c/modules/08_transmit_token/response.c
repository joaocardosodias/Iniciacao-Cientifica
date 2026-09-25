#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <curl/curl.h>

static int read_file_into_buffer(const char *path, char **out_buf, size_t *out_len)
{
    struct stat st;
    FILE *f = NULL;
    char *buf = NULL;
    size_t read_len = 0;

    if (stat(path, &st) != 0)
        return -1;

    f = fopen(path, "rb");
    if (!f)
        return -1;

    buf = malloc(st.st_size + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }

    read_len = fread(buf, 1, st.st_size, f);
    if (read_len != (size_t)st.st_size) {
        free(buf);
        fclose(f);
        return -1;
    }
    buf[read_len] = '\0';

    fclose(f);
    *out_buf = buf;
    *out_len = read_len;
    return 0;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    char *payload = NULL;
    size_t payload_len = 0;
    long response_code = 0;
    int ret = -1;

    if (read_file_into_buffer(token_path, &payload, &payload_len) != 0)
        goto cleanup;

    curl = curl_easy_init();
    if (!curl)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK)
        goto cleanup;
    if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK)
        goto cleanup;
    if (curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK)
        goto cleanup;
    if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload) != CURLE_OK)
        goto cleanup;
    if (curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)payload_len) != CURLE_OK)
        goto cleanup;
    if (curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L) != CURLE_OK)
        goto cleanup;

    if (curl_easy_perform(curl) != CURLE_OK)
        goto cleanup;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_OK)
        goto cleanup;

    if (response_code == 200)
        ret = 0;

cleanup:
    if (payload)
        free(payload);
    if (headers)
        curl_slist_free_all(headers);
    if (curl)
        curl_easy_cleanup(curl);
    return ret;
}