#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

static size_t discard_response_body(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    (void)ptr;
    (void)userdata;
    return size * nmemb;
}

static char *read_entire_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    char *buf = malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }

    size_t nread = fread(buf, 1, (size_t)sz, f);
    int read_err = ferror(f);
    fclose(f);

    if (read_err || nread != (size_t)sz) {
        free(buf);
        return NULL;
    }

    buf[nread] = '\0';
    *out_len = nread;
    return buf;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    if (endpoint == NULL || token_path == NULL) {
        return -1;
    }

    size_t body_len = 0;
    char *body = read_entire_file(token_path, &body_len);
    if (body == NULL) {
        return -1;
    }

    int result = -1;
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        free(body);
        return -1;
    }

    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL) {
        curl_easy_cleanup(curl);
        free(body);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response_body);

    CURLcode rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) {
        long status = 0;
        if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) == CURLE_OK
            && status == 200) {
            result = 0;
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(body);
    return result;
}