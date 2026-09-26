#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

static char *read_file(const char *path, size_t *out_len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }

    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    size_t read = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (read != (size_t)sz) {
        free(buf);
        return NULL;
    }

    buf[read] = '\0';
    if (out_len)
        *out_len = read;
    return buf;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    size_t token_len;
    char *token = read_file(token_path, &token_len);
    if (!token)
        return -1;

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(token);
        return -1;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        curl_easy_cleanup(curl);
        free(token);
        return -1;
    }

    CURLcode rc;
    long response_code = 0;

    rc = curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    if (rc != CURLE_OK) goto fail;
    rc = curl_easy_setopt(curl, CURLOPT_POST, 1L);
    if (rc != CURLE_OK) goto fail;
    rc = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)token_len);
    if (rc != CURLE_OK) goto fail;
    rc = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token);
    if (rc != CURLE_OK) goto fail;
    rc = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (rc != CURLE_OK) goto fail;
    rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    if (rc != CURLE_OK) goto fail;
    rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    if (rc != CURLE_OK) goto fail;

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) goto fail;

    rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (rc != CURLE_OK) goto fail;

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(token);
    return (response_code == 200) ? 0 : -1;

fail:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(token);
    return -1;
}