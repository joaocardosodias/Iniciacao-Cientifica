#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <curl/curl.h>

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *fp = fopen(token_path, "rb");
    if (!fp)
        return -1;

    struct stat st;
    if (fstat(fileno(fp), &st) != 0) {
        fclose(fp);
        return -1;
    }

    size_t filesize = st.st_size;
    char *buffer = (char *)malloc(filesize + 1);
    if (!buffer) {
        fclose(fp);
        return -1;
    }

    size_t bytes_read = fread(buffer, 1, filesize, fp);
    fclose(fp);

    if (bytes_read != filesize) {
        free(buffer);
        return -1;
    }
    buffer[filesize] = '\0';

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(buffer);
        return -1;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        curl_easy_cleanup(curl);
        free(buffer);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buffer);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

    long http_code = 0;
    if (res == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(buffer);

    return (res == CURLE_OK && http_code == 200) ? 0 : -1;
}