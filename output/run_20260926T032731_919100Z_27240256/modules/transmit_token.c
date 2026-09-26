#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <curl/curl.h>

static int read_file(const char *path, char **out_data, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    size_t sz = (size_t)st.st_size;
    char *buf = malloc(sz + 1);
    if (!buf) {
        close(fd);
        return -1;
    }
    size_t total = 0;
    while (total < sz) {
        ssize_t r = read(fd, buf + total, sz - total);
        if (r <= 0) {
            free(buf);
            close(fd);
            return -1;
        }
        total += (size_t)r;
    }
    buf[total] = '\0';
    close(fd);
    *out_data = buf;
    *out_len = total;
    return 0;
}

int transmit_token(const char *endpoint, const char *token_path) {
    char *data = NULL;
    size_t data_len = 0;
    if (read_file(token_path, &data, &data_len) != 0) {
        return -1;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(data);
        return -1;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (!headers) {
        curl_easy_cleanup(curl);
        free(data);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data_len);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    CURLcode res = curl_easy_perform(curl);
    long response_code = 0;
    int result = -1;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code == 200) {
            result = 0;
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(data);
    return result;
}