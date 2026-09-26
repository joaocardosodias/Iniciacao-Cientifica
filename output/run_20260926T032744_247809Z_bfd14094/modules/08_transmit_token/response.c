#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <curl/curl.h>

static int read_file(const char *path, char **out_buf, size_t *out_len)
{
    if (!path || !out_buf || !out_len)
        return -1;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    struct stat sb;
    if (fstat(fd, &sb) < 0) {
        close(fd);
        return -1;
    }

    size_t len = (size_t)sb.st_size;
    char *buf = malloc(len + 1);
    if (!buf) {
        close(fd);
        return -1;
    }

    size_t offset = 0;
    while (offset < len) {
        ssize_t r = read(fd, buf + offset, len - offset);
        if (r <= 0) {
            free(buf);
            close(fd);
            return -1;
        }
        offset += (size_t)r;
    }
    buf[len] = '\0';

    close(fd);
    *out_buf = buf;
    *out_len = len;
    return 0;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    if (!endpoint || !token_path)
        return -1;

    char *data = NULL;
    size_t data_len = 0;
    if (read_file(token_path, &data, &data_len) != 0)
        return -1;

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(data);
        return -1;
    }

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    if (!hdrs) {
        curl_easy_cleanup(curl);
        free(data);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data_len);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    if (rc == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    }

    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    free(data);

    if (rc != CURLE_OK)
        return -1;

    return (http_code == 200) ? 0 : -1;
}