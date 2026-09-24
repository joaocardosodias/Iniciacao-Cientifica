#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <curl/curl.h>

static size_t discard_response(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *f = NULL;
    char *buf = NULL;
    long file_size = 0;
    size_t bytes_read = 0;
    CURL *curl = NULL;
    CURLcode res;
    struct curl_slist *headers = NULL;
    long http_code = 0;
    int ret = -1;

    f = fopen(token_path, "rb");
    if (!f)
        return -1;

    if (fseek(f, 0, SEEK_END) != 0)
        goto cleanup;

    file_size = ftell(f);
    if (file_size < 0)
        goto cleanup;

    if (fseek(f, 0, SEEK_SET) != 0)
        goto cleanup;

    buf = (char *)malloc((size_t)file_size + 1);
    if (!buf)
        goto cleanup;

    bytes_read = fread(buf, 1, (size_t)file_size, f);
    if ((long)bytes_read != file_size)
        goto cleanup;

    buf[file_size] = '\0';

    fclose(f);
    f = NULL;

    curl = curl_easy_init();
    if (!curl)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers)
        goto cleanup;

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)file_size);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        goto cleanup;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    if (http_code == 200)
        ret = 0;

cleanup:
    if (f)
        fclose(f);
    if (buf)
        free(buf);
    if (headers)
        curl_slist_free_all(headers);
    if (curl)
        curl_easy_cleanup(curl);

    return ret;
}