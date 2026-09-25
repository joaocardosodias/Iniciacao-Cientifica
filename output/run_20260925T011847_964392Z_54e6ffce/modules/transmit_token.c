#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

static int read_file(const char *path, char **buf, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    char *data = malloc((size_t)file_size + 1);
    if (!data) {
        fclose(fp);
        return -1;
    }

    size_t read_bytes = fread(data, 1, (size_t)file_size, fp);
    fclose(fp);
    if (read_bytes != (size_t)file_size) {
        free(data);
        return -1;
    }
    data[read_bytes] = '\0';

    *buf = data;
    *len = read_bytes;
    return 0;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    char *token_data = NULL;
    size_t token_len = 0;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    long response_code = 0;
    int ret = -1;

    if (read_file(token_path, &token_data, &token_len) != 0)
        goto cleanup;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        goto cleanup;

    curl = curl_easy_init();
    if (!curl)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_data) != CURLE_OK)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)token_len) != CURLE_OK)
        goto cleanup;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK)
        goto cleanup;

    if (curl_easy_perform(curl) != CURLE_OK)
        goto cleanup;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_OK)
        goto cleanup;

    if (response_code == 200)
        ret = 0;

cleanup:
    if (headers)
        curl_slist_free_all(headers);
    if (curl)
        curl_easy_cleanup(curl);
    curl_global_cleanup();
    free(token_data);
    return ret;
}