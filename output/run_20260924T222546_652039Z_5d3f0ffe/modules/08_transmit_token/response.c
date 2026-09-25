#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

static size_t discard_write(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *fp;
    long sz;
    size_t nread;
    char *body;
    CURL *curl;
    struct curl_slist *headers;
    CURLcode rc;
    long http_code;
    int ret;

    if (!endpoint || !token_path)
        return -1;

    fp = fopen(token_path, "rb");
    if (!fp)
        return -1;

    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return -1;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }

    body = malloc((size_t)sz + 1);
    if (!body) {
        fclose(fp);
        return -1;
    }
    nread = fread(body, 1, (size_t)sz, fp);
    if (ferror(fp)) {
        fclose(fp);
        free(body);
        return -1;
    }
    body[nread] = '\0';
    fclose(fp);

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        free(body);
        return -1;
    }

    curl = curl_easy_init();
    if (!curl) {
        free(body);
        return -1;
    }

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (!headers) {
        curl_easy_cleanup(curl);
        free(body);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)nread);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_write);

    ret = -1;
    rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        http_code = 0;
        rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (rc == CURLE_OK && http_code == 200)
            ret = 0;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(body);
    return ret;
}